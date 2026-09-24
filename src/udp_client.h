#ifndef UDP_CLIENT_H
#define UDP_CLIENT_H

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

#endif