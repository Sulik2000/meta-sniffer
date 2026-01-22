#include <asm-generic/socket.h>
#include <netinet/in.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ucontext.h>
#include <unistd.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/ip.h>
#include <pthread.h>
#include <sys/un.h>
#include "uthash.h"
#include <signal.h>
#include <syslog.h>
#include <errno.h>

volatile sig_atomic_t running = 1;
volatile sig_atomic_t save_stats = 1;
char interface[10] = "eth0";
char interfaces[100] = "eth0;";
uint8_t size_interfaces = 5;	 // Current size of interfaces string
uint8_t current_index_iface = 0; // Current index of char in interfaces string
int set_new_iface = 0;

// If interface didn't find, return NULL. Otherwise returns string with interface name
char *get_next_interface()
{
	uint8_t start_index = current_index_iface;
	char *iface_name = malloc(10);
	while (interfaces[current_index_iface] != ';')
	{
		current_index_iface++;
		if (current_index_iface >= size_interfaces)
		{
			current_index_iface = 0;
			return NULL; // No more interfaces
		}
	}

	strncpy(iface_name, interfaces + start_index, current_index_iface - start_index);
	iface_name[current_index_iface - start_index] = '\0';
	syslog(LOG_DEBUG, "Found interface: %s", iface_name);
	current_index_iface++;
	return iface_name;
}

void insert_interface(const char *iface)
{
	char *ifaces = get_next_interface();
	while (ifaces != NULL)
	{
		if (strcmp(ifaces, iface) == 0)
		{
			free(ifaces);
			current_index_iface = 0;
			return; // Interface already exists
		}
		free(ifaces);
		ifaces = get_next_interface();
	}
	// If we reach here, the interface is new
	strncat(interfaces, iface, sizeof(interfaces) - strlen(interfaces) - 2);
	strncat(interfaces, ";", sizeof(interfaces) - strlen(interfaces) - 1);
	size_interfaces = strlen(interfaces);
}

struct IpInformation
{
	char iface[10];
	uint32_t ip_addr;
};

struct PacketStats
{
	struct IpInformation info; // Це тепер наш ключ (Key)
	int count;
	UT_hash_handle hh;
};

struct PacketStats *packets = NULL;
pthread_mutex_t stats_mutex = PTHREAD_MUTEX_INITIALIZER;
pthread_t cli_thread;

void cli_processing()
{
	int socket_fd_cli;
	struct sockaddr_un server_addr_cli;
	socket_fd_cli = socket(AF_UNIX, SOCK_STREAM, 0);
	if (socket_fd_cli < 0)
	{
		syslog(LOG_ERR, "Socket creation failed in CLI thread: %m");
		return;
	}

	server_addr_cli.sun_family = AF_UNIX;
	strncpy(server_addr_cli.sun_path, "/tmp/sniffer_daemon.sock", sizeof(server_addr_cli.sun_path) - 1);

	if (bind(socket_fd_cli, (struct sockaddr *)&server_addr_cli, sizeof(server_addr_cli)) < 0)
	{
		syslog(LOG_ERR, "Daemon is launched already. Bind failed in CLI thread: %m");
		close(socket_fd_cli);
		pthread_mutex_lock(&stats_mutex);
		running = 0;
		pthread_mutex_unlock(&stats_mutex);
		return;
	}
	listen(socket_fd_cli, 5);

	while (running)
	{
		int sock_fd = accept(socket_fd_cli, NULL, NULL);
		if (sock_fd < 0)
		{
			syslog(LOG_ERR, "Accept failed in CLI thread: %m");
			close(sock_fd);
			continue;
		}
		char buffer[256];
		int bytes_read = recv(sock_fd, buffer, sizeof(buffer) - 1, 0);
		if (bytes_read < 0)
		{
			syslog(LOG_ERR, "Receive failed in CLI thread: %m");
			close(sock_fd);
			continue;
		}
		if (bytes_read == 0)
		{
			syslog(LOG_INFO, "All statistics sent (connection closed by client)");
			close(sock_fd);
			continue;
		}
		buffer[bytes_read] = '\0'; // Null-terminate the received string

		if (strncmp(buffer, "iface:", 6) == 0)
		{
			char *iface = buffer + 6;
			syslog(LOG_INFO, "Interface change requested to: %s", iface);
			pthread_mutex_lock(&stats_mutex);

			strncpy(interface, iface, sizeof(interface) - 1);
			interface[sizeof(interface) - 1] = '\0';
			insert_interface(iface);

			pthread_mutex_unlock(&stats_mutex);
		}
		else if (strncmp(buffer, "stat:", 5) == 0)
		{
			struct PacketStats *s, *tmp;
			char *req_iface = buffer + 5;
			syslog(LOG_INFO, "Statistics request for interface: %s", req_iface);
			pthread_mutex_lock(&stats_mutex);
			HASH_ITER(hh, packets, s, tmp)
			{
				if (strcmp(req_iface, "all") == 0 || strcmp(s->info.iface, req_iface) == 0)
				{
					char buf[100];
					struct in_addr tmp_addr;
					tmp_addr.s_addr = s->info.ip_addr;
					snprintf(buf, sizeof(buf), "%s: %s: %d\n", s->info.iface, inet_ntoa(tmp_addr), s->count);
					send(sock_fd, buf, strlen(buf), 0);
				}
			}
			pthread_mutex_unlock(&stats_mutex);
			send(sock_fd, "", 0, 0); // Indicate end of statistics
			syslog(LOG_INFO, "Statistics sent for interface: %s", req_iface);
			close(sock_fd);
			continue;
		}
		else if (strncmp(buffer, "show:", 5) == 0)
		{
			struct PacketStats *s;
			syslog(LOG_INFO, "Show request for IP address %s", buffer + 5);

			struct IpInformation key;
			memset(&key, 0, sizeof(struct IpInformation));
			key.ip_addr = inet_addr(buffer + 5);
			char *iface = get_next_interface();
				
			while (iface != NULL)
			{
				syslog(LOG_INFO, "Looking on interface %s", iface);
				strncpy(key.iface, iface, sizeof(key.iface) - 1);
				pthread_mutex_lock(&stats_mutex);
				HASH_FIND(hh, packets, &key, sizeof(struct IpInformation), s);

				if (s != NULL)
				{
					char buf[100];
					struct in_addr tmp_addr;
					tmp_addr.s_addr = s->info.ip_addr;
					snprintf(buf, sizeof(buf), "%s: %s: %d\n", s->info.iface, inet_ntoa(tmp_addr), s->count);
					send(sock_fd, buf, strlen(buf), 0);
				}
				pthread_mutex_unlock(&stats_mutex);

				iface = get_next_interface();
			}
			close(sock_fd);
			continue;
		}

		close(sock_fd);
	}

	close(socket_fd_cli);
	syslog(LOG_INFO, "CLI thread socket closed");
	return;
}

void ProcessPacket(char *buffer, size_t size)
{
	struct PacketStats *s;
	// Get the IP header excluding ethernet header
	struct iphdr *iph = (struct iphdr *)(buffer);
	uint32_t ip = iph->daddr; // Destination IP address

	struct IpInformation key;
	memset(&key, 0, sizeof(struct IpInformation)); 
	key.ip_addr = ip;
	strncpy(key.iface, interface, sizeof(key.iface) - 1);

	pthread_mutex_lock(&stats_mutex);

	HASH_FIND(hh, packets, &key, sizeof(struct IpInformation), s);

	if (s == NULL)
	{
		s = (struct PacketStats *)malloc(sizeof(struct PacketStats));
		memset(s, 0, sizeof(struct PacketStats)); // Чистимо пам'ять нової структури

		s->info = key;
		s->count = 1;

		HASH_ADD(hh, packets, info, sizeof(struct IpInformation), s);
		pthread_mutex_unlock(&stats_mutex);

		struct in_addr tmp;
		tmp.s_addr = ip;
		syslog(LOG_INFO, "New IP address detected: %s on %s", inet_ntoa(tmp), interface);
	}
	else
	{
		s->count++;
		pthread_mutex_unlock(&stats_mutex);

		struct in_addr tmp;
		tmp.s_addr = ip;
		syslog(LOG_INFO, "IP address: %s; Packets: %d", inet_ntoa(tmp), s->count);
	}
}

void handle_signal(int signal)
{
	if (signal == SIGTERM) // If termination requested
		running = 0;
	if (signal == SIGINT)
	{ // If CTRL+C combination pressed
		running = 0;
		save_stats = 0;
	}
}

void save_statistics()
{
	struct PacketStats *s, *tmp;
	FILE *file = fopen("/tmp/packet_stats.txt", "w");
	if (file == NULL)
	{
		syslog(LOG_ERR, "Error opening statistics file for writing: %m");
		return;
	}
	pthread_mutex_lock(&stats_mutex);
	HASH_ITER(hh, packets, s, tmp)
	{
		struct in_addr tmp_addr;
		tmp_addr.s_addr = s->info.ip_addr;
		fprintf(file, "%s: %d: %d\n", s->info.iface, s->info.ip_addr, s->count);
	}
	pthread_mutex_unlock(&stats_mutex);
	fclose(file);
	syslog(LOG_INFO, "Statistics saved to packet_stats.txt");
}

void load_statistics()
{
	struct PacketStats *s;
	FILE *file = fopen("/tmp/packet_stats.txt", "r");
	if (file == NULL)
	{
		syslog(LOG_INFO, "No existing statistics file found.");
		return;
	}

	char line[256];
	while (fgets(line, sizeof(line), file))
	{
		char iface[10];
		uint32_t ip;
		int count;

		if (sscanf(line, "%9[^:]: %u: %d", iface, &ip, &count) == 3)
		{
			struct IpInformation key;
			memset(&key, 0, sizeof(struct IpInformation));
			strncpy(key.iface, iface, sizeof(key.iface) - 1);
			key.ip_addr = ip;

			s = (struct PacketStats *)malloc(sizeof(struct PacketStats));
			memset(s, 0, sizeof(struct PacketStats));
			s->info = key;
			s->count = count;

			HASH_ADD(hh, packets, info, sizeof(struct IpInformation), s);
			
			insert_interface(iface);
		}
	}

	fclose(file);
	syslog(LOG_INFO, "Statistics loaded from packet_stats.txt");
}

int main()
{
	openlog("sniffer_daemon", LOG_PID, LOG_DAEMON);
	syslog(LOG_INFO, "Daemon sniffer started. PID: %d", getpid());

	struct sigaction sa;
	memset(&sa, 0, sizeof(sa)); // Reseting variable
	sa.sa_handler = &handle_signal;

	sigaction(SIGTERM, &sa, NULL);
	sigaction(SIGINT, &sa, NULL);

	int socket_tcp = socket(AF_INET, SOCK_RAW, IPPROTO_TCP);
	if (socket_tcp < 0)
	{
		syslog(LOG_ERR, "Socket creation failed: %m");
		return 1;
	}

	// Default binding is to eth0 (or whatever is in interface var)
	if (setsockopt(socket_tcp, SOL_SOCKET, SO_BINDTODEVICE, interface, strlen(interface)) < 0)
	{
		syslog(LOG_ERR, "Initial bind to device %s failed: %m", interface);
	}

	char *buf = malloc(65536);
	if (!buf)
	{
		syslog(LOG_ERR, "Memory allocation failed");
		return 1;
	}

	load_statistics();

	// Launching thread to CLI
	pthread_create(&cli_thread, NULL, (void *)cli_processing, NULL);

	while (running)
	{
		if(set_new_iface)
		{
			close(socket_tcp);
			socket_tcp = socket(AF_INET, SOCK_RAW, IPPROTO_TCP);
			if (socket_tcp < 0)
			{
				syslog(LOG_ERR, "Socket recreation failed: %m");
				running = 0;
				save_stats = 1;
				continue;
			}
			if (setsockopt(socket_tcp, SOL_SOCKET, SO_BINDTODEVICE, interface, strlen(interface)) < 0)
			{
				syslog(LOG_ERR, "Re-bind to device %s failed: %m", interface);
			}
			set_new_iface = 0;
		}

		int data_size = recv(socket_tcp, buf, 65536, 0);

		if (data_size < 0)
		{
			if (errno != EINTR && errno != EAGAIN)
			{
				syslog(LOG_ERR, "Error recvfrom TCP protocol, probably intarface doesn't exist: %m");	
				sleep(1); // Avoid busy loop
				continue;
			}
			continue;
		}
		ProcessPacket(buf, data_size);
	}

	syslog(LOG_INFO, "Recieved stop signal. Cleaning up process...");
	free(buf);
	close(socket_tcp);
	unlink("/tmp/sniffer_daemon.sock");
	syslog(LOG_INFO, "Socket closed");

	pthread_mutex_lock(&stats_mutex);


	pthread_mutex_unlock(&stats_mutex);

	if (save_stats)
	{
		syslog(LOG_INFO, "Saving statistics...");
		save_statistics();
	}
	else
		syslog(LOG_INFO, "Statistics saving skipped");

	syslog(LOG_INFO, "Daemon stopped");

	// Clearing memory from hash table
	struct PacketStats *current_user, *tmp;
	HASH_ITER(hh, packets, current_user, tmp)
	{
		HASH_DEL(packets, current_user);
		free(current_user);
	}
	closelog();
	return 0;
}