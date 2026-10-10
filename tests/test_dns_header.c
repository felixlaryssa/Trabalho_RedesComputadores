#include <stdio.h>
#include <string.h>
#include "../dns_response.h"

static int fails = 0;
#define CHECK(c) do { if (!(c)) { printf("FALHOU: %s (linha %d)\n", #c, __LINE__); fails++; } } while (0)

/* Resposta fictícia do mapa (unb.br MX -> mx.unb.br), 43 bytes. */
static const unsigned char ok_pkt[] = {
    0xAB,0xCD,0x81,0x80,0x00,0x01,0x00,0x01,0x00,0x00,0x00,0x00,
    0x03,'u','n','b',0x02,'b','r',0x00,0x00,0x0F,0x00,0x01,
    0xC0,0x0C,0x00,0x0F,0x00,0x01,0x00,0x00,0x01,0x2C,0x00,0x07,
    0x00,0x0A,0x02,'m','x',0xC0,0x0C
};

static dns_resp_status_t run(const unsigned char *p, size_t n, uint16_t id)
{
    dns_response_header_t h;
    if (dns_parse_header(p, n, &h) != 0) return DNS_RESP_INVALID;
    return dns_check_header(&h, n, id);
}

int main(void)
{
    unsigned char p[sizeof ok_pkt];
    dns_response_header_t h;

    /* campos */
    CHECK(dns_parse_header(ok_pkt, sizeof ok_pkt, &h) == 0);
    CHECK(h.id == 0xABCD && h.flags == 0x8180);
    CHECK(h.qr == 1 && h.rd == 1 && h.ra == 1 && h.aa == 0 && h.tc == 0);
    CHECK(h.opcode == 0 && h.rcode == 0);
    CHECK(h.qdcount == 1 && h.ancount == 1 && h.nscount == 0 && h.arcount == 0);

    /* sucesso */
    CHECK(run(ok_pkt, sizeof ok_pkt, 0xABCD) == DNS_RESP_OK);
    /* ID errado */
    CHECK(run(ok_pkt, sizeof ok_pkt, 0x1234) == DNS_RESP_INVALID);

    /* menor que o header / nulos */
    CHECK(dns_parse_header(ok_pkt, 11, &h) == -1);
    CHECK(dns_parse_header(NULL, 20, &h) == -1);
    CHECK(dns_parse_header(ok_pkt, 20, NULL) == -1);
    CHECK(run(ok_pkt, 0, 0xABCD) == DNS_RESP_INVALID);

    /* NXDOMAIN: RCODE 3, ANCOUNT 0 */
    memcpy(p, ok_pkt, sizeof p);
    p[3] = 0x83; p[7] = 0;
    CHECK(run(p, 24, 0xABCD) == DNS_RESP_NXDOMAIN);

    /* sem MX: RCODE 0, ANCOUNT 0 */
    memcpy(p, ok_pkt, sizeof p);
    p[7] = 0;
    CHECK(run(p, 24, 0xABCD) == DNS_RESP_NO_MX);

    /* SERVFAIL (2) e REFUSED (5) */
    memcpy(p, ok_pkt, sizeof p); p[3] = 0x82;
    CHECK(run(p, sizeof p, 0xABCD) == DNS_RESP_INVALID);
    p[3] = 0x85;
    CHECK(run(p, sizeof p, 0xABCD) == DNS_RESP_INVALID);

    /* QR = 0 (é consulta, não resposta) */
    memcpy(p, ok_pkt, sizeof p); p[2] = 0x01;
    CHECK(run(p, sizeof p, 0xABCD) == DNS_RESP_INVALID);

    /* TC = 1 */
    memcpy(p, ok_pkt, sizeof p); p[2] = 0x83;
    CHECK(run(p, sizeof p, 0xABCD) == DNS_RESP_INVALID);

    /* QDCOUNT = 2 */
    memcpy(p, ok_pkt, sizeof p); p[5] = 2;
    CHECK(run(p, sizeof p, 0xABCD) == DNS_RESP_INVALID);

    /* ANCOUNT absurdo (0xFFFF) para 43 bytes */
    memcpy(p, ok_pkt, sizeof p); p[6] = 0xFF; p[7] = 0xFF;
    CHECK(run(p, sizeof p, 0xABCD) == DNS_RESP_INVALID);

    /* só o header, prometendo 1 pergunta: malformada */
    CHECK(run(ok_pkt, 12, 0xABCD) == DNS_RESP_INVALID);

    puts(fails ? "Testes com falha." : "Todos os testes passaram.");
    return fails != 0;
}