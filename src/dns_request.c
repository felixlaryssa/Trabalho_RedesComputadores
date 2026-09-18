#include "dns_request.h"

#include <arpa/inet.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>


int encode_domain_name(
    const char *domain,
    unsigned char *buffer
)
{
    if (domain == NULL || buffer == NULL) {
        return -1;
    }

    int buffer_pos = 0;
    const char *label_start = domain;
    const char *current = domain;

    while (1) {

        if (*current == '.' || *current == '\0') {

            int label_length = current - label_start;

            /*
             * Uma label DNS pode possuir no máximo 63 caracteres.
             */
            if (label_length <= 0 || label_length > 63) {
                return -1;
            }

            buffer[buffer_pos++] = (unsigned char)label_length;

            for (int i = 0; i < label_length; i++) {
                buffer[buffer_pos++] = label_start[i];
            }

            if (*current == '\0') {
                break;
            }

            label_start = current + 1;
        }

        current++;
    }

    /*
     * Zero indica o final do nome DNS.
     */
    buffer[buffer_pos++] = 0;

    return buffer_pos;
}


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
     * Geração de um Transaction ID de 16 bits.
     */
    static int initialized = 0;

    if (!initialized) {
        srand((unsigned int)time(NULL));
        initialized = 1;
    }

    *transaction_id = (uint16_t)(rand() & 0xFFFF);

    dns_header_t header;

    header.id = htons(*transaction_id);

    /*
     * 0x0100:
     * consulta padrão com Recursion Desired (RD = 1).
     */
    header.flags = htons(0x0100);

    /*
     * Apenas uma pergunta.
     */
    header.qdcount = htons(1);

    header.ancount = htons(0);
    header.nscount = htons(0);
    header.arcount = htons(0);

    /*
     * Copia os 12 bytes do cabeçalho para o pacote.
     */
    memcpy(
        buffer,
        &header,
        sizeof(dns_header_t)
    );

    int offset = DNS_HEADER_SIZE;

    /*
     * Codifica o domínio.
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
     * Precisamos de mais quatro bytes:
     *
     * 2 bytes - QTYPE
     * 2 bytes - QCLASS
     */
    if (offset + 4 > buffer_size) {
        return -1;
    }

    /*
     * QTYPE = 15 = MX
     */
    uint16_t qtype = htons(DNS_TYPE_MX);

    memcpy(
        buffer + offset,
        &qtype,
        sizeof(qtype)
    );

    offset += sizeof(qtype);

    /*
     * QCLASS = 1 = IN
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