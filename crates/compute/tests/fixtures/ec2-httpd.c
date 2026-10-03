/* Minimal static HTTP workload for the isolated EC2/ALB compatibility gate. */
#include <arpa/inet.h>
#include <errno.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

int main(int argc, char **argv) {
    if (argc != 2) {
        return 2;
    }
    char *end = NULL;
    long port = strtol(argv[1], &end, 10);
    if (*end || port < 1 || port > 65535) {
        return 2;
    }
    int listener = socket(AF_INET, SOCK_STREAM, 0);
    if (listener < 0) {
        return 3;
    }
    int reuse = 1;
    setsockopt(listener, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(reuse));
    struct sockaddr_in address = {
        .sin_family = AF_INET,
        .sin_port = htons((unsigned short)port),
        .sin_addr.s_addr = htonl(INADDR_LOOPBACK),
    };
    if (bind(listener, (struct sockaddr *)&address, sizeof(address)) != 0 ||
        listen(listener, 16) != 0) {
        close(listener);
        return 4;
    }
    static const char response[] =
        "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: 16\r\n"
        "Connection: close\r\n\r\nhello-locallycloud";
    for (;;) {
        int client = accept(listener, NULL, NULL);
        if (client < 0) {
            if (errno == EINTR) {
                continue;
            }
            break;
        }
        char request[1024];
        (void)read(client, request, sizeof(request));
        (void)write(client, response, sizeof(response) - 1);
        close(client);
    }
    close(listener);
    return 5;
}
