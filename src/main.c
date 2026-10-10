#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <sys/select.h>
#include <sys/time.h>

#include "dns_request.h"
#include "udp_client.h"
#include "dns_response.h"

#define QUERY_BUFFER_SIZE 512
#define RESPONSE_BUFFER_SIZE 4096

int main(int argc, char *argv[])
{
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
    if (udp_client_configure_server(dns_server_ip, &server_address) == -1) {
        fprintf(stderr, "Erro controlado, sem crash: endereco IPv4 do servidor DNS invalido: %s\n", dns_server_ip);
        udp_client_close(&socket_fd);
        return 1;
    }

    ssize_t response_size = -1;
    int max_retries = 3;

    // Lógica de Timeout (2s) e 3 Tentativas
    for (int i = 0; i < max_retries; i++) {
        if (udp_client_send_query(socket_fd, query, (size_t)query_size, &server_address) == -1) {
            perror("Erro ao enviar consulta");
            udp_client_close(&socket_fd);
            return 1;
        }

        fd_set fds;
        FD_ZERO(&fds);
        FD_SET(socket_fd, &fds);

        struct timeval tv;
        tv.tv_sec = 2; // Timeout de 2 segundos exigido no cronograma
        tv.tv_usec = 0;

        int ready = select(socket_fd + 1, &fds, NULL, NULL, &tv);
        if (ready > 0) {
            response_size = udp_client_receive_response(socket_fd, response, sizeof(response), NULL);
            break; // Sai do loop se recebeu a resposta
        } else if (ready < 0) {
            perror("Erro no select");
            break;
        }
        // Se ready == 0 (timeout), o loop continua e tenta de novo
    }

    udp_client_close(&socket_fd);

    if (response_size <= 0) {
        fprintf(stderr, "Falha apos ate 3 tentativas\n");
        return 1;
    }

    // Parser da resposta DNS
    dns_mx_record_t mx_record;
    dns_resp_status_t status = dns_parse_mx_response(response, (size_t)response_size, transaction_id, &mx_record);

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