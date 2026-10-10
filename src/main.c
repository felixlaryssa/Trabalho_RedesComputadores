#include <errno.h>
#include <stdint.h>
#include <stdio.h>

#include "dns_request.h"
#include "udp_client.h"

#define QUERY_BUFFER_SIZE 512
#define RESPONSE_BUFFER_SIZE 4096

int main(int argc, char *argv[])
{
    if (argc != 3) {
        fprintf(
            stderr,
            "Uso: %s <dominio> <servidor_dns>\n",
            argv[0]
        );

        return 1;
    }

    const char *domain = argv[1];
    const char *dns_server_ip = argv[2];

    uint8_t query[QUERY_BUFFER_SIZE];
    uint8_t response[RESPONSE_BUFFER_SIZE];

    uint16_t transaction_id;

    int query_size = build_dns_query(
        domain,
        query,
        sizeof(query),
        &transaction_id
    );

    if (query_size < 0) {
        fprintf(
            stderr,
            "Erro ao montar consulta DNS.\n"
        );

        return 1;
    }

    printf("Dominio: %s\n", domain);
    printf("Servidor DNS: %s\n", dns_server_ip);
    printf("Transaction ID: 0x%04X\n", transaction_id);
    printf("Consulta DNS MX criada com sucesso.\n");
    printf("Tamanho do pacote: %d bytes\n", query_size);

    printf("\nPacote DNS enviado:\n");

    for (int i = 0; i < query_size; ++i) {
        printf("%02X ", query[i]);

        if ((i + 1) % 16 == 0) {
            printf("\n");
        }
    }

    printf("\n");

    /*
     * Criação do socket UDP.
     */
    int socket_fd = udp_client_open();

    if (socket_fd == -1) {
        perror("Erro ao criar socket UDP");
        return 1;
    }

    /*
     * Configuração do endereço IPv4 e da porta DNS 53.
     */
    struct sockaddr_in server_address;

    if (udp_client_configure_server(
            dns_server_ip,
            &server_address
        ) == -1) {

        fprintf(
            stderr,
            "Erro: endereco IPv4 do servidor DNS invalido: %s\n",
            dns_server_ip
        );

        udp_client_close(&socket_fd);
        return 1;
    }

    /*
     * Endereço do servidor que enviar a resposta.
     */
    struct sockaddr_in response_sender;

    /*
     * Quantidade de envios realizados.
     */
    unsigned int attempts = 0;

    /*
     * Envia a consulta e aguarda a resposta.
     *
     * Cada tentativa espera até 2 segundos.
     * São realizadas no máximo 3 tentativas.
     */
    ssize_t response_size = udp_client_exchange_with_retry(
        socket_fd,
        query,
        (size_t)query_size,
        &server_address,
        response,
        sizeof(response),
        &response_sender,
        &attempts
    );

    if (response_size == -1) {
        if (errno == ETIMEDOUT) {
            fprintf(
                stderr,
                "Servidor DNS nao respondeu apos %u tentativas.\n",
                attempts
            );
        } else {
            perror("Erro na comunicacao com o servidor DNS");
        }

        udp_client_close(&socket_fd);
        return 1;
    }

    printf(
        "\nResposta recebida com %zd bytes apos %u tentativa(s).\n",
        response_size,
        attempts
    );

    printf("\nPacote DNS recebido:\n");

    for (ssize_t i = 0; i < response_size; ++i) {
        printf("%02X ", response[i]);

        if ((i + 1) % 16 == 0) {
            printf("\n");
        }
    }

    printf("\n");

    /*
     * Futuramente, a Pessoa 3 deverá receber:
     *
     * response
     * response_size
     *
     * Exemplo:
     *
     * parse_dns_response(response, (size_t)response_size);
     */

    if (udp_client_close(&socket_fd) == -1) {
        perror("Erro ao fechar socket UDP");
        return 1;
    }

    return 0;
}