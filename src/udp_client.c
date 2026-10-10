#include "udp_client.h"

#include <arpa/inet.h>
#include <errno.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

int udp_client_open(void)
{
    return socket(AF_INET, SOCK_DGRAM, 0);
}

int udp_client_close(int *socket_fd)
{
    if (socket_fd == NULL) {
        errno = EINVAL;
        return -1;
    }

    if (*socket_fd < 0) {
        return 0;
    }

    if (close(*socket_fd) == -1) {
        return -1;
    }

    *socket_fd = -1;
    return 0;
}

int udp_client_configure_server(const char *dns_ip,
                                struct sockaddr_in *server_address)
{
    if (dns_ip == NULL || server_address == NULL) {
        errno = EINVAL;
        return -1;
    }

    memset(server_address, 0, sizeof(*server_address));
    server_address->sin_family = AF_INET;
    server_address->sin_port = htons(DNS_PORT);

    int conversion_result =
        inet_pton(AF_INET, dns_ip, &server_address->sin_addr);

    if (conversion_result == 1) {
        return 0;
    }

    if (conversion_result == 0) {
        errno = EINVAL;
    }

    return -1;
}