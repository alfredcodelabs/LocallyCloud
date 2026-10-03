#include <arpa/inet.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <unistd.h>

static int connect_once(unsigned short port, const char *ip) {
    struct sockaddr_in address = {
        .sin_family = AF_INET,
        .sin_port = htons(port),
        .sin_addr.s_addr = htonl(INADDR_LOOPBACK),
    };
    if (ip && inet_pton(AF_INET, ip, &address.sin_addr) != 1) return 8;
    for (int attempt = 0; attempt < 500; ++attempt) {
        int socket_fd = socket(AF_INET, SOCK_STREAM, 0);
        if (socket_fd < 0) return 3;
        if (connect(socket_fd, (struct sockaddr *)&address, sizeof(address)) == 0) {
            if (write(socket_fd, "ping", 4) != 4) return 5;
            char reply[4];
            if (read(socket_fd, reply, 4) != 4) return 6;
            close(socket_fd);
            if (reply[0] != 'p' || reply[1] != 'o' || reply[2] != 'n' || reply[3] != 'g') return 7;
            return 0;
        }
        close(socket_fd);
        usleep(20000);
    }
    return 4;
}

int main(int argc, char **argv) {
    if (argc < 2 || argc > 4) return 2;
    unsigned short port = (unsigned short)atoi(argv[1]);
    if (argc == 2) {
        if (connect_once(port, NULL) != 0) return 4;
    } else {
        for (int i = 2; i < argc; ++i) {
            int result = connect_once(port, argv[i]);
            if (result != 0) return result;
        }
    }
    puts("isolated-loopback-ok");
    return 0;
}
