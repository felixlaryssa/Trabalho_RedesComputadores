#include "dns_request.h"

#include <arpa/inet.h>
#include <errno.h>
#include <stddef.h>
#include <string.h>
#include <sys/random.h>
#include <sys/types.h>


/*
 * O cabeçalho DNS deve possuir exatamente
 * 12 bytes.
 */
_Static_assert(
    sizeof(dns_header_t) == DNS_HEADER_SIZE,
    "dns_header_t deve possuir 12 bytes"
);


/*
 * Gera um Transaction ID aleatório
 * de 16 bits.
 *
 * Retorno:
 *
 *  0 : sucesso
 * -1 : erro
 */
static int generate_transaction_id(
    uint16_t *transaction_id
)
{
    if (transaction_id == NULL) {
        return -1;
    }

    ssize_t result;

    do {
        result = getrandom(
            transaction_id,
            sizeof(*transaction_id),
            0
        );

    } while (
        result < 0 &&
        errno == EINTR
    );

    if (
        result !=
        (ssize_t)sizeof(*transaction_id)
    ) {
        return -1;
    }

    return 0;
}


/*
 * Codifica um domínio para o formato DNS.
 *
 * Exemplo:
 *
 * unb.br
 *
 * vira:
 *
 * 03 u n b 02 b r 00
 */
int encode_domain_name(
    const char *domain,
    unsigned char *buffer,
    int buffer_size
)
{
    if (
        domain == NULL ||
        buffer == NULL ||
        buffer_size <= 0
    ) {
        return -1;
    }

    size_t domain_length =
        strlen(domain);

    /*
     * Domínio vazio ou maior que o limite
     * permitido não é aceito.
     */
    if (
        domain_length == 0 ||
        domain_length > DNS_MAX_NAME_LENGTH
    ) {
        return -1;
    }

    size_t buffer_pos = 0;
    size_t label_start = 0;

    /*
     * Percorre o domínio procurando
     * os separadores '.'.
     */
    for (
        size_t i = 0;
        i <= domain_length;
        ++i
    ) {
        if (
            domain[i] != '.' &&
            domain[i] != '\0'
        ) {
            continue;
        }

        size_t label_length =
            i - label_start;

        /*
         * Cada label deve possuir entre
         * 1 e 63 caracteres.
         */
        if (
            label_length == 0 ||
            label_length >
                DNS_MAX_LABEL_LENGTH
        ) {
            return -1;
        }

        /*
         * Verifica se ainda existe espaço
         * suficiente no buffer.
         */
        if (
            buffer_pos +
            1 +
            label_length >
            (size_t)buffer_size
        ) {
            return -1;
        }

        /*
         * Primeiro byte:
         * tamanho da label.
         */
        buffer[buffer_pos++] =
            (unsigned char)label_length;

        /*
         * Copia os caracteres da label.
         */
        memcpy(
            buffer + buffer_pos,
            domain + label_start,
            label_length
        );

        buffer_pos +=
            label_length;

        label_start =
            i + 1;
    }

    /*
     * O nome DNS termina com byte zero.
     */
    if (
        buffer_pos + 1 >
        (size_t)buffer_size
    ) {
        return -1;
    }

    buffer[buffer_pos++] = 0;

    return (int)buffer_pos;
}


/*
 * Monta o pacote de consulta DNS MX.
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
        buffer_size <
            DNS_HEADER_SIZE + 5
    ) {
        return -1;
    }

    /*
     * Inicializa todo o buffer com zero.
     */
    memset(
        buffer,
        0,
        (size_t)buffer_size
    );

    /*
     * Gera Transaction ID aleatório
     * de 16 bits.
     */
    if (
        generate_transaction_id(
            transaction_id
        ) != 0
    ) {
        return -1;
    }

    dns_header_t header;

    /*
     * Transaction ID.
     */
    header.id =
        htons(*transaction_id);

    /*
     * Flags = 0x0100
     *
     * Consulta DNS padrão com
     * Recursion Desired (RD = 1).
     */
    header.flags =
        htons(0x0100);

    /*
     * Uma pergunta.
     */
    header.qdcount =
        htons(1);

    /*
     * Nenhum registro de resposta,
     * autoridade ou adicional
     * na consulta.
     */
    header.ancount =
        htons(0);

    header.nscount =
        htons(0);

    header.arcount =
        htons(0);

    /*
     * Copia o cabeçalho para o início
     * do pacote.
     */
    memcpy(
        buffer,
        &header,
        sizeof(header)
    );

    int offset =
        DNS_HEADER_SIZE;

    /*
     * Codifica o domínio logo após
     * o cabeçalho.
     */
    int domain_size =
        encode_domain_name(
            domain,
            buffer + offset,
            buffer_size - offset
        );

    if (domain_size < 0) {
        return -1;
    }

    offset +=
        domain_size;

    /*
     * Ainda precisamos de quatro bytes:
     *
     * QTYPE  = 2 bytes
     * QCLASS = 2 bytes
     */
    if (
        offset + 4 >
        buffer_size
    ) {
        return -1;
    }

    /*
     * QTYPE = 15 = MX.
     */
    uint16_t qtype =
        htons(DNS_TYPE_MX);

    memcpy(
        buffer + offset,
        &qtype,
        sizeof(qtype)
    );

    offset +=
        (int)sizeof(qtype);

    /*
     * QCLASS = 1 = IN.
     */
    uint16_t qclass =
        htons(DNS_CLASS_IN);

    memcpy(
        buffer + offset,
        &qclass,
        sizeof(qclass)
    );

    offset +=
        (int)sizeof(qclass);

    return offset;
}