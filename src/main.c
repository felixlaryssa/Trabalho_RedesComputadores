#include <stdio.h>
#include <stdint.h>

#include "dns_request.h"

#define BUFFER_SIZE 512


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
    const char *dns_server = argv[2];

    unsigned char packet[BUFFER_SIZE];

    uint16_t transaction_id;

    int packet_size = build_dns_query(
        domain,
        packet,
        BUFFER_SIZE,
        &transaction_id
    );

    if (packet_size < 0) {

        fprintf(
            stderr,
            "Erro ao montar consulta DNS.\n"
        );

        return 1;
    }

    printf(
        "Dominio: %s\n",
        domain
    );

    printf(
        "Servidor DNS: %s\n",
        dns_server
    );

    printf(
        "Transaction ID: 0x%04X\n",
        transaction_id
    );

    printf(
        "Consulta DNS MX criada com sucesso.\n"
    );

    printf(
        "Tamanho do pacote: %d bytes\n",
        packet_size
    );

    printf(
        "\nPacote DNS:\n"
    );

    for (int i = 0; i < packet_size; i++) {

        printf(
            "%02X ",
            packet[i]
        );

        if ((i + 1) % 16 == 0) {
            printf("\n");
        }
    }

    printf("\n");

    return 0;
}