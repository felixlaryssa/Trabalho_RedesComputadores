#include "dns_request.h"

#include <arpa/inet.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <sys/random.h>


static uint16_t generate_transaction_id(void)
{
    uint16_t id;

    ssize_t result;

    do {
        result = getrandom(
            &id,
            sizeof(id),
            0
        );
    } while (result < 0 && errno == EINTR);

    if (result != sizeof(id)) {
        id = (uint16_t)rand();
    }

    return id;
}


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

            int label_length =
                (int)(current - label_start);

            /*
             * Cada label DNS pode ter no máximo
             * 63 caracteres.
             */
            if (
                label_length <= 0 ||
                label_length > 63
            ) {
                return -1;
            }

            buffer[buffer_pos++] =
                (unsigned char)label_length;

            for (
                int i = 0;
                i < label_length;
                i++
            ) {
                buffer[buffer_pos++] =
                    (unsigned char)label_start[i];
            }

            if (*current == '\0') {
                break;
            }

            label_start = current + 1;
        }

        current++;
    }

    /*
     * Zero marca o final do nome DNS.
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

    memset(
        buffer,
        0,
        (size_t)buffer_size
    );

    /*
     * Transaction ID aleatório de 16 bits.
     */
    *transaction_id =
        generate_transaction_id();

    dns_header_t header;

    header.id =
        htons(*transaction_id);

    header.flags =
        htons(0x0100);

    header.qdcount =
        htons(1);

    header.ancount =
        htons(0);

    header.nscount =
        htons(0);

    header.arcount =
        htons(0);

    memcpy(
        buffer,
        &header,
        sizeof(header)
    );

    int offset = DNS_HEADER_SIZE;

    int domain_size =
        encode_domain_name(
            domain,
            buffer + offset
        );

    if (domain_size < 0) {
        return -1;
    }

    offset += domain_size;

    if (offset + 4 > buffer_size) {
        return -1;
    }

    /*
     * QTYPE = MX.
     */
    uint16_t qtype =
        htons(DNS_TYPE_MX);

    memcpy(
        buffer + offset,
        &qtype,
        sizeof(qtype)
    );

    offset += sizeof(qtype);

    /*
     * QCLASS = IN.
     */
    uint16_t qclass =
        htons(DNS_CLASS_IN);

    memcpy(
        buffer + offset,
        &qclass,
        sizeof(qclass)
    );

    offset += sizeof(qclass);

    return offset;
}