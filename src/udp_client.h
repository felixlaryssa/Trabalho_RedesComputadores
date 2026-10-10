#ifndef UDP_CLIENT_H
#define UDP_CLIENT_H

#include <stddef.h>
#include <stdint.h>
#include <netinet/in.h>
#include <sys/types.h>

#define DNS_PORT 53
#define DNS_TIMEOUT_SECONDS 2
#define DNS_MAX_ATTEMPTS 3

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

/**
 * Envia uma consulta DNS completa em um único datagrama UDP.
 *
 * Parâmetros:
 *   socket_fd: descritor de um socket UDP aberto;
 *   query: buffer montado pelo módulo da Pessoa 1;
 *   query_size: quantidade de bytes válidos em query;
 *   server_address: servidor DNS IPv4 configurado na porta 53.
 *
 * Retorno:
 *   >= 0: quantidade de bytes enviados;
 *     -1: erro; errno informa a causa.
 */
ssize_t udp_client_send_query(int socket_fd,
                              const uint8_t *query,
                              size_t query_size,
                              const struct sockaddr_in *server_address);

/**
 * Recebe a resposta DNS bruta e a preserva em response_buffer.
 *
 * A função não acrescenta '\0', pois uma mensagem DNS contém dados binários.
 * O parser deve usar exatamente o número de bytes retornado.
 *
 * Parâmetros:
 *   socket_fd: descritor de um socket UDP aberto;
 *   response_buffer: destino dos bytes recebidos;
 *   response_capacity: capacidade total do buffer;
 *   sender_address: recebe o endereço do remetente; pode ser NULL.
 *
 * Retorno:
 *   >= 0: quantidade de bytes recebidos;
 *     -1: erro; errno informa a causa.
 */
ssize_t udp_client_receive_response(int socket_fd,
                                    uint8_t *response_buffer,
                                    size_t response_capacity,
                                    struct sockaddr_in *sender_address);
/**
 * Configura o socket para aguardar no máximo 2 segundos
 * pela resposta do servidor.
 */
int udp_client_set_receive_timeout(int socket_fd);

/**
 * Envia a consulta e espera a resposta.
 *
 * Em caso de timeout, repete o envio até completar
 * no máximo 3 tentativas.
 *
 * Retorna:
 *   > 0: quantidade de bytes recebidos;
 *    -1: erro na comunicação.
 *
 * Após três timeouts, errno será ETIMEDOUT.
 */
ssize_t udp_client_exchange_with_retry(
    int socket_fd,
    const uint8_t *query,
    size_t query_size,
    const struct sockaddr_in *server_address,
    uint8_t *response_buffer,
    size_t response_capacity,
    struct sockaddr_in *sender_address,
    unsigned int *attempts_made);
#endif