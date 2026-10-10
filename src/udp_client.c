#include "udp_client.h"

#include <arpa/inet.h>
#include <errno.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>
#include <sys/time.h>

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

ssize_t udp_client_send_query(int socket_fd,
                              const uint8_t *query,
                              size_t query_size,
                              const struct sockaddr_in *server_address)
{
    if (socket_fd < 0 || query == NULL || query_size == 0 ||
        server_address == NULL) {
        errno = EINVAL;
        return -1;
    }

    ssize_t bytes_sent = sendto(socket_fd,
                                query,
                                query_size,
                                0,
                                (const struct sockaddr *)server_address,
                                sizeof(*server_address));

    if (bytes_sent >= 0 && (size_t)bytes_sent != query_size) {
        errno = EIO;
        return -1;
    }

    return bytes_sent;
}

ssize_t udp_client_receive_response(int socket_fd,
                                    uint8_t *response_buffer,
                                    size_t response_capacity,
                                    struct sockaddr_in *sender_address)
{
    if (socket_fd < 0 || response_buffer == NULL || response_capacity == 0) {
        errno = EINVAL;
        return -1;
    }

    struct sockaddr *sender = NULL;
    socklen_t *sender_size_pointer = NULL;
    socklen_t sender_size = 0;

    if (sender_address != NULL) {
        memset(sender_address, 0, sizeof(*sender_address));
        sender = (struct sockaddr *)sender_address;
        sender_size = sizeof(*sender_address);
        sender_size_pointer = &sender_size;
    }

    return recvfrom(socket_fd,
                    response_buffer,
                    response_capacity,
                    0,
                    sender,
                    sender_size_pointer);
}

int udp_client_set_receive_timeout(int socket_fd)
{
    if (socket_fd < 0) {
        errno = EINVAL;
        return -1;
    }

    const struct timeval timeout = {
        .tv_sec = DNS_TIMEOUT_SECONDS,
        .tv_usec = 0,
    };

    return setsockopt(socket_fd,
                      SOL_SOCKET,
                      SO_RCVTIMEO,
                      &timeout,
                      sizeof(timeout));
}

ssize_t udp_client_exchange_with_retry(
    int socket_fd,
    const uint8_t *query,
    size_t query_size,
    const struct sockaddr_in *server_address,
    uint8_t *response_buffer,
    size_t response_capacity,
    struct sockaddr_in *sender_address,
    unsigned int *attempts_made)
{
    if (attempts_made != NULL) {
        *attempts_made = 0;
    }

    if (socket_fd < 0 ||
        query == NULL ||
        query_size == 0 ||
        server_address == NULL ||
        response_buffer == NULL ||
        response_capacity == 0) {
        errno = EINVAL;
        return -1;
    }

    if (udp_client_set_receive_timeout(socket_fd) == -1) {
        return -1;
    }

    for (unsigned int attempt = 1;
         attempt <= DNS_MAX_ATTEMPTS;
         ++attempt) {

        if (attempts_made != NULL) {
            *attempts_made = attempt;
        }

        if (udp_client_send_query(socket_fd,
                                  query,
                                  query_size,
                                  server_address) == -1) {
            return -1;
        }

        ssize_t bytes_received;

        do {
            bytes_received = udp_client_receive_response(
                socket_fd,
                response_buffer,
                response_capacity,
                sender_address);
        } while (bytes_received == -1 && errno == EINTR);

        if (bytes_received >= 0) {
            return bytes_received;
        }

        /*
         * EAGAIN e EWOULDBLOCK indicam que o tempo
         * de espera terminou sem resposta.
         */
        if (errno != EAGAIN && errno != EWOULDBLOCK) {
            return -1;
        }
    }

    errno = ETIMEDOUT;
    return -1;
}