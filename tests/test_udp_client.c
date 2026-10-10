#include "udp_client.h"

#include <arpa/inet.h>
#include <stdio.h>

#define CHECK(condition, message)          \
    do {                                   \
        if (!(condition)) {                \
            fprintf(stderr, "%s\n", message); \
            return 1;                      \
        }                                  \
    } while (0)

static int test_socket_lifecycle(void)
{
    int socket_fd = udp_client_open();
    CHECK(socket_fd >= 0, "ERRO: não foi possível criar o socket UDP.");
    CHECK(udp_client_close(&socket_fd) == 0,
          "ERRO: não foi possível fechar o socket UDP.");
    CHECK(socket_fd == -1,
          "ERRO: descritor não foi invalidado depois de close().");
    return 0;
}

static int test_valid_dns_server(void)
{
    struct sockaddr_in server_address;

    CHECK(udp_client_configure_server("8.8.8.8", &server_address) == 0,
          "ERRO: um IPv4 válido foi rejeitado.");
    CHECK(server_address.sin_family == AF_INET,
          "ERRO: família do endereço não é AF_INET.");
    CHECK(ntohs(server_address.sin_port) == DNS_PORT,
          "ERRO: porta configurada não é 53.");
    CHECK(ntohl(server_address.sin_addr.s_addr) == 0x08080808U,
          "ERRO: endereço IPv4 foi convertido incorretamente.");
    return 0;
}

static int test_invalid_dns_server(void)
{
    struct sockaddr_in server_address;

    CHECK(udp_client_configure_server("abc", &server_address) == -1,
          "ERRO: o IP inválido 'abc' foi aceito.");
    CHECK(udp_client_configure_server("999.1.1.1", &server_address) == -1,
          "ERRO: o IP fora da faixa foi aceito.");
    CHECK(udp_client_configure_server(NULL, &server_address) == -1,
          "ERRO: um ponteiro de IP nulo foi aceito.");
    CHECK(udp_client_configure_server("1.1.1.1", NULL) == -1,
          "ERRO: um endereço de destino nulo foi aceito.");
    return 0;
}

int main(void)
{
    CHECK(test_socket_lifecycle() == 0, "Falha no teste do socket.");
    CHECK(test_valid_dns_server() == 0, "Falha no teste de IPv4 válido.");
    CHECK(test_invalid_dns_server() == 0, "Falha no teste de IPv4 inválido.");

    puts("OK: socket UDP e servidor DNS IPv4:53 configurados corretamente.");
    return 0;
}