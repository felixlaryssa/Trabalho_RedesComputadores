#include "udp_client.h"

#include <arpa/inet.h>
#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>

#define RESPONSE_BUFFER_SIZE 512

#define CHECK(condition, message)             \
    do {                                      \
        if (!(condition)) {                   \
            fprintf(stderr, "%s\n", message); \
            return -1;                        \
        }                                     \
    } while (0)

static int test_server_configuration(void)
{
    struct sockaddr_in server_address;

    CHECK(udp_client_configure_server("8.8.8.8", &server_address) == 0,
          "ERRO: IPv4 válido foi rejeitado.");
    CHECK(server_address.sin_family == AF_INET,
          "ERRO: família não configurada como AF_INET.");
    CHECK(ntohs(server_address.sin_port) == DNS_PORT,
          "ERRO: porta DNS não configurada como 53.");
    CHECK(udp_client_configure_server("abc", &server_address) == -1,
          "ERRO: IPv4 inválido foi aceito.");
    return 0;
}

static int create_local_receiver(struct sockaddr_in *receiver_address)
{
    int receiver_fd = udp_client_open();
    CHECK(receiver_fd >= 0, "ERRO: falha ao criar socket receptor.");

    memset(receiver_address, 0, sizeof(*receiver_address));
    receiver_address->sin_family = AF_INET;
    receiver_address->sin_port = htons(0);
    receiver_address->sin_addr.s_addr = htonl(INADDR_LOOPBACK);

    if (bind(receiver_fd,
             (const struct sockaddr *)receiver_address,
             sizeof(*receiver_address)) == -1) {
        perror("bind");
        udp_client_close(&receiver_fd);
        return -1;
    }

    socklen_t address_size = sizeof(*receiver_address);
    if (getsockname(receiver_fd,
                    (struct sockaddr *)receiver_address,
                    &address_size) == -1) {
        perror("getsockname");
        udp_client_close(&receiver_fd);
        return -1;
    }

    return receiver_fd;
}

static int test_send_and_receive(void)
{
    /* Cabeçalho binário semelhante ao início de uma consulta DNS. */
    const uint8_t query[] = {
        0x12, 0x34, 0x01, 0x00, 0x00, 0x01,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00
    };
    uint8_t response[RESPONSE_BUFFER_SIZE] = {0};
    struct sockaddr_in receiver_address;
    struct sockaddr_in sender_address;
    int receiver_fd = create_local_receiver(&receiver_address);
    CHECK(receiver_fd >= 0, "ERRO: não foi possível preparar o receptor.");

    int sender_fd = udp_client_open();
    if (sender_fd == -1) {
        perror("socket");
        udp_client_close(&receiver_fd);
        return -1;
    }

    ssize_t bytes_sent = udp_client_send_query(sender_fd,
                                                query,
                                                sizeof(query),
                                                &receiver_address);
    if (bytes_sent != (ssize_t)sizeof(query)) {
        perror("sendto");
        udp_client_close(&sender_fd);
        udp_client_close(&receiver_fd);
        return -1;
    }

    ssize_t bytes_received = udp_client_receive_response(receiver_fd,
                                                         response,
                                                         sizeof(response),
                                                         &sender_address);
    if (bytes_received != bytes_sent) {
        fprintf(stderr, "ERRO: tamanho recebido difere do enviado.\n");
        udp_client_close(&sender_fd);
        udp_client_close(&receiver_fd);
        return -1;
    }

    if (memcmp(query, response, sizeof(query)) != 0) {
        fprintf(stderr, "ERRO: buffer recebido foi alterado.\n");
        udp_client_close(&sender_fd);
        udp_client_close(&receiver_fd);
        return -1;
    }

    if (sender_address.sin_family != AF_INET) {
        fprintf(stderr, "ERRO: remetente recebido não é IPv4.\n");
        udp_client_close(&sender_fd);
        udp_client_close(&receiver_fd);
        return -1;
    }

    CHECK(udp_client_close(&sender_fd) == 0,
          "ERRO: falha ao fechar socket emissor.");
    CHECK(udp_client_close(&receiver_fd) == 0,
          "ERRO: falha ao fechar socket receptor.");
    return 0;
}

static int test_invalid_arguments(void)
{
    uint8_t buffer[16] = {0};
    struct sockaddr_in address;

    errno = 0;
    CHECK(udp_client_send_query(-1, buffer, sizeof(buffer), &address) == -1 &&
              errno == EINVAL,
          "ERRO: envio aceitou descritor inválido.");

    errno = 0;
    CHECK(udp_client_send_query(0, NULL, sizeof(buffer), &address) == -1 &&
              errno == EINVAL,
          "ERRO: envio aceitou buffer nulo.");

    errno = 0;
    CHECK(udp_client_receive_response(-1, buffer, sizeof(buffer), NULL) == -1 &&
              errno == EINVAL,
          "ERRO: recepção aceitou descritor inválido.");

    errno = 0;
    CHECK(udp_client_receive_response(0, NULL, sizeof(buffer), NULL) == -1 &&
              errno == EINVAL,
          "ERRO: recepção aceitou buffer nulo.");
    return 0;
}

int main(void)
{
    CHECK(test_server_configuration() == 0,
          "Falha no teste de configuração do servidor.");
    CHECK(test_send_and_receive() == 0,
          "Falha no teste local de envio e recepção.");
    CHECK(test_invalid_arguments() == 0,
          "Falha no teste de argumentos inválidos.");

    puts("OK: envio e recepção UDP preservaram o datagrama completo.");
    return 0;
}