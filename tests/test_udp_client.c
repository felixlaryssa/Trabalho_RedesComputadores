#include "udp_client.h"

#include <errno.h>
#include <stdio.h>
#include <string.h>

#define OPEN_CLOSE_CYCLES 1000

int main(void)
{
    for (int i = 0; i < OPEN_CLOSE_CYCLES; ++i) {
        int socket_fd = udp_client_open();

        if (socket_fd == -1) {
            fprintf(stderr, "Falha ao criar socket UDP: %s\n", strerror(errno));
            return 1;
        }

        if (udp_client_close(&socket_fd) == -1) {
            fprintf(stderr, "Falha ao fechar socket UDP: %s\n", strerror(errno));
            return 1;
        }

        if (socket_fd != -1) {
            fprintf(stderr, "Descritor nao foi invalidado apos close().\n");
            return 1;
        }
    }

    puts("OK: socket UDP criado e fechado corretamente em 1000 ciclos.");
    return 0;
}