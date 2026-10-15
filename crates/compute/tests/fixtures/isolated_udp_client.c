/* Send "ping" datagrams to <ip>:<port> until a "pong" reply arrives (at most ~5 s). */
#include <arpa/inet.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <unistd.h>

int main(int argc, char **argv) {
    if (argc != 3) return 2;
    struct sockaddr_in address = {
        .sin_family = AF_INET,
        .sin_port = htons((unsigned short)atoi(argv[2])),
    };
    if (inet_pton(AF_INET, argv[1], &address.sin_addr) != 1) return 8;
    int socket_fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (socket_fd < 0) return 3;
    struct timeval timeout = {.tv_sec = 0, .tv_usec = 50000};
    if (setsockopt(socket_fd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout)) != 0) return 9;
    for (int attempt = 0; attempt < 100; ++attempt) {
        /* Errors are expected until the host binds the endpoint. */
        sendto(socket_fd, "ping", 4, 0, (struct sockaddr *)&address, sizeof(address));
        char reply[4];
        if (recv(socket_fd, reply, sizeof(reply), 0) == 4 && reply[0] == 'p' && reply[1] == 'o'
            && reply[2] == 'n' && reply[3] == 'g') {
            puts("isolated-udp-ok");
            return 0;
        }
    }
    return 4;
}
