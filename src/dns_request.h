#ifndef DNS_REQUEST_H
#define DNS_REQUEST_H

#include <stdint.h>

#define DNS_HEADER_SIZE 12
#define DNS_TYPE_MX 15
#define DNS_CLASS_IN 1

#define DNS_MAX_LABEL_LENGTH 63
#define DNS_MAX_NAME_LENGTH 253

/*
 * Cabeçalho padrão de uma mensagem DNS.
 *
 * Cada campo possui 16 bits.
 * Tamanho total: 12 bytes.
 */
typedef struct {
    uint16_t id;
    uint16_t flags;
    uint16_t qdcount;
    uint16_t ancount;
    uint16_t nscount;
    uint16_t arcount;
} dns_header_t;

/*
 * Codifica um domínio para o formato utilizado
 * no protocolo DNS.
 *
 * Exemplo:
 *
 * unb.br
 *
 * torna-se:
 *
 * 03 u n b 02 b r 00
 *
 * Retorno:
 *
 * > 0 : quantidade de bytes escritos
 * -1  : erro
 */
int encode_domain_name(
    const char *domain,
    unsigned char *buffer,
    int buffer_size
);

/*
 * Monta uma consulta DNS do tipo MX,
 * classe IN.
 *
 * Retorno:
 *
 * > 0 : tamanho total do pacote
 * -1  : erro
 */
int build_dns_query(
    const char *domain,
    unsigned char *buffer,
    int buffer_size,
    uint16_t *transaction_id
);

#endif