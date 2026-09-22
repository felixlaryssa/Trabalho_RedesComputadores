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
 * Retorna o número de bytes escritos no buffer
 * ou -1 em caso de erro.
 */
int encode_domain_name(
    const char *domain,
    unsigned char *buffer
);

/*
 * Monta uma consulta DNS do tipo MX / classe IN.
 *
 * Retorna o tamanho total do pacote
 * ou -1 em caso de erro.
 */
int build_dns_query(
    const char *domain,
    unsigned char *buffer,
    int buffer_size,
    uint16_t *transaction_id
)
{
    if (
        domain == NULL ||
        buffer == NULL ||
        transaction_id == NULL ||
        buffer_size < DNS_HEADER_SIZE
    ) {
        return -1;
    }

    memset(buffer, 0, buffer_size);

    /*
     * Gera um Transaction ID aleatório de 16 bits.
     */
    *transaction_id = generate_transaction_id();

    dns_header_t header;

    header.id = htons(*transaction_id);

    /*
     * Consulta padrão com Recursion Desired (RD = 1).
     */
    header.flags = htons(0x0100);

    /*
     * Uma única pergunta.
     */
    header.qdcount = htons(1);

    /*
     * Os demais contadores começam zerados.
     */
    header.ancount = htons(0);
    header.nscount = htons(0);
    header.arcount = htons(0);

    memcpy(
        buffer,
        &header,
        sizeof(dns_header_t)
    );

    int offset = DNS_HEADER_SIZE;

    /*
     * Codifica o domínio no formato DNS.
     */
    int domain_size = encode_domain_name(
        domain,
        buffer + offset
    );

    if (domain_size < 0) {
        return -1;
    }

    offset += domain_size;

    /*
     * Precisamos de mais 4 bytes:
     *
     * 2 bytes para QTYPE
     * 2 bytes para QCLASS
     */
    if (offset + 4 > buffer_size) {
        return -1;
    }

    /*
     * QTYPE = MX (15).
     */
    uint16_t qtype = htons(DNS_TYPE_MX);

    memcpy(
        buffer + offset,
        &qtype,
        sizeof(qtype)
    );

    offset += sizeof(qtype);

    /*
     * QCLASS = IN (1).
     */
    uint16_t qclass = htons(DNS_CLASS_IN);

    memcpy(
        buffer + offset,
        &qclass,
        sizeof(qclass)
    );

    offset += sizeof(qclass);

    return offset;
}

#endif