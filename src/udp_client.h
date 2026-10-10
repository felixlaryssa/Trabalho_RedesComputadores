#ifndef UDP_CLIENT_H
#define UDP_CLIENT_H

#include <netinet/in.h>

#define DNS_PORT 53

/**
 * Cria um socket IPv4 do tipo UDP.
 *
 * Retorno:
 *   >= 0: descritor do socket criado;
 *   -1: erro; errno permanece definido por socket().
 */
int udp_client_open(void);

/**
 * Fecha um socket aberto.
 *
 * O ponteiro permite invalidar o descritor depois do fechamento e evita
 * fechamentos duplicados acidentais.
 *
 * Retorno:
 *   0: socket fechado ou já estava marcado como fechado;
 *   -1: argumento inválido ou erro de close(); errno informa a causa.
 */
int udp_client_close(int *socket_fd);

/**
 * Preenche o endereço de um servidor DNS IPv4 na porta 53.
 *
 * Retorno:
 *   0: endereço configurado com sucesso;
 *  -1: argumento nulo ou IPv4 inválido; errno informa a causa.
 */
int udp_client_configure_server(const char *dns_ip,
                                struct sockaddr_in *server_address);

#endif