#include "udp_client.h"

#include <errno.h>
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