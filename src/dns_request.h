#ifndef DNS_REQUEST_H
#define DNS_REQUEST_H

#include <stdint.h>

#define DNS_HEADER_SIZE 12
#define DNS_TYPE_MX 15
#define DNS_CLASS_IN 1

typedef struct {
    uint16_t id;
    uint16_t flags;
    uint16_t qdcount;
    uint16_t ancount;
    uint16_t nscount;
    uint16_t arcount;
} dns_header_t;

/*
 * Codifica um domínio para o formato utilizado pelo protocolo DNS.
 *
 * Exemplo:
 * unb.br
 *
 * torna-se:
 * 03 u n b 02 b r 00
 *
 * Retorna o número de bytes escritos no buffer.
 */
int encode_domain_name(
    const char *domain,
    unsigned char *buffer
);

/*
 * Monta uma consulta DNS do tipo MX / classe IN.
 *
 * Retorna o tamanho total do pacote ou -1 em caso de erro.
 */
int build_dns_query(
    const char *domain,
    unsigned char *buffer,
    int buffer_size,
    uint16_t *transaction_id
);

#endif