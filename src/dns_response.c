#include "dns_response.h"

#include <string.h>

/* Lê 16 bits big-endian sem depender de alinhamento nem de ntohs. */
static uint16_t read_u16(const unsigned char *p)
{
    return (uint16_t)(((uint16_t)p[0] << 8) | (uint16_t)p[1]);
}


int dns_parse_header(
    const unsigned char *buffer,
    size_t len,
    dns_response_header_t *header
)
{
    if (buffer == NULL || header == NULL || len < DNS_RESP_HEADER_SIZE) {
        return -1;
    }

    header->id      = read_u16(buffer + 0);
    header->flags   = read_u16(buffer + 2);
    header->qdcount = read_u16(buffer + 4);
    header->ancount = read_u16(buffer + 6);
    header->nscount = read_u16(buffer + 8);
    header->arcount = read_u16(buffer + 10);

    header->qr     = (uint8_t)((header->flags & DNS_FLAG_QR) != 0);
    header->opcode = (uint8_t)((header->flags & DNS_FLAG_OPCODE) >> 11);
    header->aa     = (uint8_t)((header->flags & DNS_FLAG_AA) != 0);
    header->tc     = (uint8_t)((header->flags & DNS_FLAG_TC) != 0);
    header->rd     = (uint8_t)((header->flags & DNS_FLAG_RD) != 0);
    header->ra     = (uint8_t)((header->flags & DNS_FLAG_RA) != 0);
    header->rcode  = (uint8_t)(header->flags & DNS_FLAG_RCODE);

    return 0;
}


dns_resp_status_t dns_check_header(
    const dns_response_header_t *header,
    size_t len,
    uint16_t expected_id
)
{
    if (header == NULL || len < DNS_RESP_HEADER_SIZE) {
        return DNS_RESP_INVALID;
    }

    /* Resposta de outra transação (ou pacote forjado). */
    if (header->id != expected_id) {
        return DNS_RESP_INVALID;
    }

    /* Precisa ser resposta, de consulta padrão, e não truncada. */
    if (header->qr != 1 || header->opcode != 0 || header->tc != 0) {
        return DNS_RESP_INVALID;
    }

    /* Enviamos exatamente uma pergunta; o servidor deve ecoá-la. */
    if (header->qdcount != 1) {
        return DNS_RESP_INVALID;
    }

    /*
     * Os contadores não podem prometer mais registros do que cabem nos
     * bytes recebidos (cada Question ocupa >= 5 B e cada RR >= 11 B).
     * Evita confiar em contadores absurdos antes de percorrer o pacote.
     */
    {
        size_t available = len - DNS_RESP_HEADER_SIZE;
        size_t needed =
            (size_t)header->qdcount * DNS_MIN_QUESTION_SIZE +
            ((size_t)header->ancount +
             (size_t)header->nscount +
             (size_t)header->arcount) * DNS_MIN_RR_SIZE;

        if (needed > available) {
            return DNS_RESP_INVALID;
        }
    }

    if (header->rcode == DNS_RCODE_NXDOMAIN) {
        return DNS_RESP_NXDOMAIN;
    }

    /* SERVFAIL, REFUSED, FORMERR, NOTIMP etc. */
    if (header->rcode != DNS_RCODE_NOERROR) {
        return DNS_RESP_INVALID;
    }

    if (header->ancount == 0) {
        return DNS_RESP_NO_MX;
    }

    return DNS_RESP_OK;
}


int dns_decode_name(
    const unsigned char *buffer,
    size_t len,
    size_t start_offset,
    char *out,
    size_t out_size,
    size_t *end_offset
)
{
    if (buffer == NULL || out == NULL || out_size == 0) {
        return -1;
    }

    if (start_offset >= len) {
        return -1;
    }

    size_t cur = start_offset;
    size_t out_pos = 0;
    int    first_label = 1;

    int    jumps = 0;
    size_t return_offset = 0;
    int    followed_pointer = 0;

    while (1) {

        if (cur >= len) {
            return -1;
        }

        unsigned char b0 = buffer[cur];

        if ((b0 & 0xC0) == 0xC0) {

            /* Ponteiro de compressão: 2 bytes. */
            if (cur + 1 >= len) {
                return -1;
            }

            if (!followed_pointer) {
                /*
                 * A posição de retorno do chamador avança só 2 bytes
                 * (o ponteiro em si), e somente na primeira vez que
                 * seguimos um ponteiro.
                 */
                return_offset = cur + 2;
                followed_pointer = 1;
            }

            jumps++;
            if (jumps > DNS_MAX_NAME_POINTER_JUMPS) {
                /* Excesso de saltos: provável loop. */
                return -1;
            }

            size_t target =
                (size_t)((b0 & 0x3F) << 8) | (size_t)buffer[cur + 1];

            /*
             * Pondo de compressão só pode apontar para trás (RFC 1035);
             * exigir isso impede loops, já que o offset sempre diminui.
             */
            if (target >= cur) {
                return -1;
            }

            cur = target;
            continue;
        }

        if ((b0 & 0xC0) != 0x00) {
            /* Bits 01 ou 10: reservado/inválido. */
            return -1;
        }

        if (b0 == 0x00) {
            /* Fim do nome. */
            cur++;
            if (!followed_pointer) {
                return_offset = cur;
            }
            break;
        }

        /* Label comum: b0 é o tamanho (1 a 63). */
        unsigned int label_len = b0 & 0x3F;

        if (cur + 1 + label_len > len) {
            return -1;
        }

        if (!first_label) {
            if (out_pos + 1 >= out_size) {
                return -1;
            }
            out[out_pos++] = '.';
        }

        if (out_pos + label_len >= out_size) {
            return -1;
        }

        memcpy(out + out_pos, buffer + cur + 1, label_len);
        out_pos += label_len;
        first_label = 0;

        cur += 1 + label_len;
    }

    out[out_pos] = '\0';

    if (end_offset != NULL) {
        *end_offset = return_offset;
    }

    return (int)out_pos;
}


dns_resp_status_t dns_parse_mx_response(
    const unsigned char *buffer,
    size_t len,
    uint16_t expected_id,
    dns_mx_record_t *mx_out
)
{
    dns_response_header_t header;
    dns_resp_status_t     status;

    if (buffer == NULL || mx_out == NULL) {
        return DNS_RESP_INVALID;
    }

    if (dns_parse_header(buffer, len, &header) != 0) {
        return DNS_RESP_INVALID;
    }

    status = dns_check_header(&header, len, expected_id);

    /* NXDOMAIN, resposta inválida ou "sem MX" já resolvidos pelo header. */
    if (status != DNS_RESP_OK) {
        return status;
    }

    size_t offset = DNS_RESP_HEADER_SIZE;
    char   name_buf[DNS_MAX_NAME_LEN];

    /* --- Question: pular QDCOUNT (== 1) entradas. --- */
    for (uint16_t i = 0; i < header.qdcount; i++) {

        size_t next_offset;

        if (
            dns_decode_name(
                buffer, len, offset,
                name_buf, sizeof(name_buf),
                &next_offset
            ) < 0
        ) {
            return DNS_RESP_INVALID;
        }

        offset = next_offset;

        /* QTYPE (2) + QCLASS (2) */
        if (offset + 4 > len) {
            return DNS_RESP_INVALID;
        }

        offset += 4;
    }

    /* --- Answer: percorrer ANCOUNT RRs, guardando o MX de menor preference. --- */
    int      have_mx = 0;
    uint16_t best_preference = 0;
    char     best_exchange[DNS_MAX_NAME_LEN];

    for (uint16_t i = 0; i < header.ancount; i++) {

        size_t next_offset;

        if (
            dns_decode_name(
                buffer, len, offset,
                name_buf, sizeof(name_buf),
                &next_offset
            ) < 0
        ) {
            return DNS_RESP_INVALID;
        }

        offset = next_offset;

        /* TYPE(2) + CLASS(2) + TTL(4) + RDLENGTH(2) = 10 bytes. */
        if (offset + 10 > len) {
            return DNS_RESP_INVALID;
        }

        uint16_t rtype    = read_u16(buffer + offset);
        uint16_t rclass   = read_u16(buffer + offset + 2);
        /* TTL (buffer + offset + 4, 4 bytes) não é usado neste trabalho. */
        uint16_t rdlength = read_u16(buffer + offset + 8);

        size_t rdata_start = offset + 10;

        if (rdata_start + rdlength > len) {
            return DNS_RESP_INVALID;
        }

        if (rtype == DNS_RTYPE_MX && rclass == DNS_RCLASS_IN) {

            if (rdlength < 2) {
                return DNS_RESP_INVALID;
            }

            uint16_t preference = read_u16(buffer + rdata_start);

            int exch_len = dns_decode_name(
                buffer, len, rdata_start + 2,
                name_buf, sizeof(name_buf),
                NULL
            );

            if (exch_len < 0) {
                return DNS_RESP_INVALID;
            }

            if (!have_mx || preference < best_preference) {
                best_preference = preference;
                memcpy(best_exchange, name_buf, (size_t)exch_len + 1);
            }

            have_mx = 1;
        }

        /* RR de outro tipo (A, AAAA, CNAME, ...): ignorar e seguir. */
        offset = rdata_start + rdlength;
    }

    if (!have_mx) {
        /*
         * RCODE = 0 mas nenhum RR do tipo MX/IN entre as Answers
         * (ex.: só A/AAAA). Trata-se do mesmo caso de "sem MX".
         */
        return DNS_RESP_NO_MX;
    }

    mx_out->preference = best_preference;
    memcpy(mx_out->exchange, best_exchange, sizeof(best_exchange));

    return DNS_RESP_OK;
}