#include <errno.h>
#include <stdint.h>
#include <stdio.h>

#include "dns_request.h"
#include "udp_client.h"
#include "dns_response.h"

#define QUERY_BUFFER_SIZE 512
#define RESPONSE_BUFFER_SIZE 4096

int main(int argc, char *argv[])
{
    // Cenário: Argumentos faltando
    if (argc != 3) {
        fprintf(stderr, "Uso: %s <dominio> <servidor_dns>\n", argv[0]);
        return 1;
    }

    const char *domain = argv[1];
    const char *dns_server_ip = argv[2];
    uint8_t query[QUERY_BUFFER_SIZE];
    uint8_t response[RESPONSE_BUFFER_SIZE];
    uint16_t transaction_id;

    int query_size = build_dns_query(domain, query, sizeof(query), &transaction_id);
    if (query_size < 0) {
        fprintf(stderr, "Erro ao montar consulta DNS.\n");
        return 1;
    }

    int socket_fd = udp_client_open();
    if (socket_fd == -1) {
        perror("Erro ao criar socket UDP");
        return 1;
    }

    struct sockaddr_in server_address;
    // Cenário: IP inválido
    if (udp_client_configure_server(dns_server_ip, &server_address) == -1) {
        fprintf(stderr, "Erro controlado, sem crash: endereco IPv4 do servidor DNS invalido: %s\n", dns_server_ip);
        udp_client_close(&socket_fd);
        return 1;
    }

    struct sockaddr_in response_sender;
    unsigned int attempts = 0;

    // Comunicação UDP com timeout e 3 tentativas
    ssize_t response_size = udp_client_exchange_with_retry(
        socket_fd, query, (size_t)query_size, &server_address,
        response, sizeof(response), &response_sender, &attempts);

    if (response_size == -1) {
        // Cenário: DNS sem resposta
        if (errno == ETIMEDOUT) {
            fprintf(stderr, "Falha apos ate 3 tentativas\n");
        } else {
            perror("Erro na comunicacao com o servidor DNS");
        }
        udp_client_close(&socket_fd);
        return 1;
    }

    udp_client_close(&socket_fd);

    // Parser da resposta DNS
    dns_mx_record_t mx_record;
    dns_resp_status_t status = dns_parse_mx_response(response, (size_t)response_size, transaction_id, &mx_record);

    // Tratamento dos cenários de saída
    if (status == DNS_RESP_NXDOMAIN) {
        printf("Dominio %s nao encontrado\n", domain);
    } else if (status == DNS_RESP_NO_MX) {
        printf("Dominio %s nao possui entrada MX\n", domain);
    } else if (status == DNS_RESP_OK) {
        printf("%s <> %s\n", domain, mx_record.exchange);
    } else {
        fprintf(stderr, "Erro: Resposta DNS invalida ou malformada.\n");
        return 1;
    }

    return 0;
}