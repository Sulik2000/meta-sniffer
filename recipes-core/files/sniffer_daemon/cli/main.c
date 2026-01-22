#include <stdio.h>
#include <sys/socket.h>
#include <fcntl.h>
#include <sys/un.h>
#include <string.h>

int socket_fd;
struct sockaddr_un server_addr;

void show_help()
{
    printf("Available commands:\n");
    printf("  --help          Show this help message\n");
    printf("  start         Start the sniffer daemon\n");
    printf("  stop          Stop the sniffer daemon\n");
    printf("  show [ip] count        Show the status of the sniffer daemon\n");
    printf("  select iface [iface]         Display current packet statistics\n");
    printf("  stat [iface]   Clear all saved packet statistics\n");
}

int main(int argc, char *argv[])
{
    if (argc == 1)
    {
        printf("No arguments provided. Use --help to see available options.\n");
        return 0;
    }

    if (strcmp(argv[1], "--help") == 0)
    {
        show_help();
        return 0;
    }

    if (strcmp(argv[1], "start") == 0)
    {
        system("service sniffer start");
        printf("Sniffer daemon started successfully.\n");
        return 0;
    }

    if (strcmp(argv[1], "stop") == 0)
    {
        system("service sniffer stop");
        printf("Sniffer daemon stopped successfully.\n");
        return 0;
    }

    socket_fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (socket_fd < 0)
    {
        perror("Socket creation failed");
        return 1;
    }

    server_addr.sun_family = AF_UNIX;
    strncpy(server_addr.sun_path, "/tmp/sniffer_daemon.sock", sizeof(server_addr.sun_path));

    int len = sizeof(server_addr.sun_family) + strlen(server_addr.sun_path);

    if (connect(socket_fd, (struct sockaddr *)&server_addr, len) < 0)
    {
        perror("Connection to daemon failed. Probably daemon is not running.");
        close(socket_fd);
        return 1;
    }

    if (strcmp(argv[1], "select") == 0)
    {
        if (strcmp(argv[2], "iface") == 0 && argc == 4)
        {
            printf("Selecting interface: %s\n", argv[3]);
            char cmd[40];
            strcat(cmd, "iface:");
            strcat(cmd, argv[3]);
            // Send command to daemon
            send(socket_fd, cmd, strlen(cmd), 0);
            return 0;
        }
        else
        {
            printf("Invalid arguments for select command.\n");
            return 1;
        }
        printf("Stopping the sniffer daemon...\n");
        // Implement stop logic here
        return 0;
    }

    if (strcmp(argv[argc - 2], "stat") == 0)
    {
        if (argc != 3)
        {
            perror("Invalid arguments for stat command.\n");
            return 1;
        }

        printf("Requesting statistics for %s\n", argv[argc - 1]);

        char cmd[40];
        strcat(cmd, "stat:");
        strcat(cmd, argv[argc - 1]);
        send(socket_fd, cmd, strlen(cmd), 0);
        char buffer[100];
        while (socket_fd > 0)
        {
            int bytes_read = recv(socket_fd, buffer, sizeof(buffer) - 1, 0);
            if (bytes_read < 0)
            {
                perror("Receive from daemon failed");
                close(socket_fd);
                return 1;
            }
            if (bytes_read == 0)
                break;

            buffer[bytes_read] = '\0';
            printf("%s", buffer);
        }
        printf("Statistics for %s received successfully.\n", argv[argc - 1]);
        return 0;
    }

    if (strcmp(argv[argc - 3], "show") == 0)
    {
        char cmd[40] = "";
        char buffer[100];
        char ip[20] = "";
        strncpy(ip, argv[argc - 2], sizeof(ip) - 1);
        if (strcmp(argv[argc - 1], "count") != 0)
        {
            printf("Invalid arguments for show command.\n");
            return 1;
        }
        strcat(cmd, "show:");
        strcat(cmd, ip);
        send(socket_fd, cmd, strlen(cmd), 0);
        while (1)
        {
            int bytes = recv(socket_fd, buffer, sizeof(buffer) - 1, 0);
            if (bytes < 0)
            {
                perror("Receive from daemon failed");
                close(socket_fd);
                return 1;
            }
            if (bytes == 0)
            {
                printf("All statistics claimed\n");
                close(socket_fd);
                break;
            }
            buffer[bytes] = '\0';
            printf("%s", buffer);
        }
        return 0;
    }
    printf("Unknown command. Use --help to see available options.\n");
}