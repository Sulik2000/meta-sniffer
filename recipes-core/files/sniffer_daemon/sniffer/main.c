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
#include <stdio.h>
#include <arpa/inet.h>
#include <netinet/ip.h>
#include <pthread.h>
#include <sys/un.h>
#include "uthash.h"
#include <signal.h>

volatile sig_atomic_t running = 1;
volatile sig_atomic_t save_stats = 1;
char interface[10] = "eth0\0";

struct PacketInfo
{
	char iface[10];
	int count;
};

struct PacketStats
{
	uint32_t ip_addr;
	struct PacketInfo info;
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
		perror("Socket creation failed in CLI thread");
		return;
	}

	server_addr_cli.sun_family = AF_UNIX;
	strncpy(server_addr_cli.sun_path, "/tmp/sniffer_daemon.sock", sizeof(server_addr_cli.sun_path) - 1);

	if (bind(socket_fd_cli, (struct sockaddr *)&server_addr_cli, sizeof(server_addr_cli)) < 0)
	{
		perror("Daemon is launched already. Bind failed in CLI thread");
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
			perror("Accept failed in CLI thread");
			close(sock_fd);
			continue;
		}
		char buffer[256];
		int bytes_read = recv(sock_fd, buffer, sizeof(buffer) - 1, 0);
		if (bytes_read < 0)
		{
			perror("Receive failed in CLI thread");
			close(sock_fd);
			continue;
		}
		if (bytes_read == 0)
		{
			printf("All statistics sent\n");
			close(sock_fd);
			continue;
		}
		buffer[bytes_read] = '\0'; // Null-terminate the received string
		// Hadle iface command
		if (strncmp(buffer, "iface:", 6) == 0)
		{
			char *iface = buffer + 6;
			printf("Interface change requested to: %s\n", iface);
			pthread_mutex_lock(&stats_mutex);
			strcpy(interface, iface);
			if (setsockopt(socket_fd_cli, SOL_SOCKET, SO_BINDTODEVICE, iface, strlen(iface) + 1) < 0)
			{
				perror("Failed to change interface");
				pthread_mutex_unlock(&stats_mutex);
				close(sock_fd);
				continue;
			}

			// Clearing memory from hash table
			struct PacketStats *current_user, *tmp;
			HASH_ITER(hh, packets, current_user, tmp)
			{
				HASH_DEL(packets, current_user);
				free(current_user);
			}

			pthread_mutex_unlock(&stats_mutex);
			printf("Interface changed successfully to: %s\n", iface);
		}
		// Processing command stat [iface]
		if (strncmp(buffer, "stat:", 5) == 0)
		{
			struct PacketStats *s, *tmp;
			char *iface = buffer + 5;
			printf("Statistics request for interface: %s\n", iface);
			pthread_mutex_lock(&stats_mutex);
			HASH_ITER(hh, packets, s, tmp)
			{
				if (strcmp(s->info.iface, iface) == 0)
				{
					char buf[100];
					struct in_addr tmp_addr;
					tmp_addr.s_addr = s->ip_addr;
					sprintf(buf, "%s: %s: %d\n", s->info.iface, inet_ntoa(tmp_addr), s->info.count);
					send(sock_fd, buf, strlen(buf), 0);
				}
			}
			pthread_mutex_unlock(&stats_mutex);
			send(sock_fd, "", 0, 0); // Indicate end of statistics
			printf("Statistics sent for interface: %s\n", iface);
			close(sock_fd);
			continue;
		}
		if (strncmp(buffer, "show:", 5) == 0)
		{
			struct PacketStats *s;
			printf("Show request for IP address %s\n", buffer + 5);
			printf("%s\n", buffer);
			pthread_mutex_lock(&stats_mutex);
			uint32_t ip_addr = inet_addr(buffer + 5);
			HASH_FIND(hh, packets, &ip_addr, sizeof(uint32_t), s);
			if (s == NULL)
			{
				char msg[] = "No data for this IP address\n";
				send(sock_fd, msg, strlen(msg), 0);
			}
			else
			{
				char buf[100];
				struct in_addr tmp_addr;
				tmp_addr.s_addr = s->ip_addr;
				sprintf(buf, "%s: %s: %d\n", s->info.iface, inet_ntoa(tmp_addr), s->info.count);
				send(sock_fd, buf, strlen(buf), 0);
			}
			pthread_mutex_unlock(&stats_mutex);
			close(sock_fd);
			continue;
		}

		close(sock_fd);
	}

	close(socket_fd_cli);
	printf("CLI thread socket closed\n");
	return;
}

void ProcessPacket(char *buffer, size_t size)
{
	struct PacketStats *s;
	// Get the IP header excluding ethernet header
	struct iphdr *iph = (struct iphdr *)(buffer);
	uint32_t ip = iph->daddr; // Destination IP address
	pthread_mutex_lock(&stats_mutex);
	HASH_FIND(hh, packets, &ip, sizeof(uint32_t), s); // UT hash table function
	if (s == NULL)
	{
		s = (struct PacketStats *)malloc(sizeof(struct PacketStats));
		s->ip_addr = ip;
		s->info.count = 1;
		strncpy(s->info.iface, interface, sizeof(s->info.iface) - 1);
		s->info.iface[sizeof(s->info.iface) - 1] = '\0';
		// Optionally set iface if needed: strncpy(s->info.iface, interface, sizeof(s->info.iface));

		HASH_ADD(hh, packets, ip_addr, sizeof(uint32_t), s);
		pthread_mutex_unlock(&stats_mutex);

		struct in_addr tmp;
		tmp.s_addr = ip;
		printf("New IP address detected: %s\n", inet_ntoa(tmp));
	}
	else
	{
		s->info.count++;
		strncpy(s->info.iface, interface, sizeof(s->info.iface) - 1);
		s->info.iface[sizeof(s->info.iface) - 1] = '\0';
		pthread_mutex_unlock(&stats_mutex);
		struct in_addr tmp;
		tmp.s_addr = ip;
		printf("IP address: %s; Packets: %d\n", inet_ntoa(tmp), s->info.count);
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
	FILE *file = fopen("packet_stats.txt", "w");
	if (file == NULL)
	{
		fprintf(stderr, "Error opening statistics file for writing\n");
		return;
	}
	pthread_mutex_lock(&stats_mutex);
	HASH_ITER(hh, packets, s, tmp)
	{
		struct in_addr tmp_addr;
		tmp_addr.s_addr = s->ip_addr;
		fprintf(file, "%s: %s: %d\n", s->info.iface, inet_ntoa(tmp_addr), s->info.count);
	}
	pthread_mutex_unlock(&stats_mutex);
	fclose(file);
	printf("Statistics saved to packet_stats.txt\n");
}

void load_statistics()
{
	struct PacketStats *s, *tmp;
	FILE *file = fopen("packet_stats.txt", "r");
	if (file == NULL)
	{
		printf("No existing statistics file found.\n");
		return;
	}

	char line[256];
	while (fgets(line, sizeof(line), file))
	{
		struct in_addr addr;
		char iface[10];
		int count;
		if (sscanf(line, "%31[^:]: %31[^:]: %d", iface, inet_ntoa(addr), &count) == 3)
		{
			s = (struct PacketStats *)malloc(sizeof(struct PacketStats));
			s->ip_addr = addr.s_addr;
			strncpy(s->info.iface, iface, sizeof(s->info.iface) - 1);
			s->info.iface[sizeof(s->info.iface) - 1] = '\0';
			s->info.count = count;
			// Optionally set iface if needed: memset(s->info.iface, 0, sizeof(s->info.iface));
			HASH_ADD(hh, packets, ip_addr, sizeof(uint32_t), s);
		}
	}

	fclose(file);
	printf("Statistics loaded from packet_stats.txt\n");
}

int main()
{
	struct sigaction sa;
	memset(&sa, 0, sizeof(sa)); // Reseting variable
	sa.sa_handler = &handle_signal;

	sigaction(SIGTERM, &sa, NULL);

	sigaction(SIGINT, &sa, NULL);

	printf("Daemon sniffer started. PID: %d", getpid());

	fflush(stdout);

	int socket_tcp = socket(AF_INET, SOCK_RAW, IPPROTO_TCP);
	setsockopt(socket_tcp, SOL_SOCKET, SO_BINDTODEVICE, "eth0", strlen("eth0") + 1); // Default binging is to wlp3s0
	socklen_t saddr_size;
	struct sockaddr saddr;

	char *buf = malloc(65536);
	load_statistics();

	// Launching thread to CLI
	pthread_t cli_thread;
	pthread_create(&cli_thread, NULL, (void *)cli_processing, NULL);
	while (running)
	{
		pthread_mutex_lock(&stats_mutex);
		int data_size = recvfrom(socket_tcp, buf, 65536, 0, &saddr, &saddr_size);
		pthread_mutex_unlock(&stats_mutex);
		if (data_size < 0)
		{
			fprintf(stderr, "Error recvfrom TCP protocol \n");
			sleep(3);
			continue;
		}
		ProcessPacket(buf, data_size);
	}

	printf("Recieved stop signal. Cleaning up process... \n");
	free(buf);
	close(socket_tcp);
	unlink("/tmp/sniffer_daemon.sock");
	printf("Socket closed\n");

	pthread_mutex_lock(&stats_mutex);

	// Clearing memory from hash table
	struct PacketStats *current_user, *tmp;
	HASH_ITER(hh, packets, current_user, tmp)
	{
		HASH_DEL(packets, current_user);
		free(current_user);
	}

	pthread_mutex_unlock(&stats_mutex);

	if (save_stats)
	{
		printf("Saving statistics... \n");
		save_statistics();
	}
	else
		printf("Statistics saving skipped\n");

	printf("Daemon stopped\n");

	fflush(stdout);

	return 0;
}