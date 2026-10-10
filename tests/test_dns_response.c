#include <stdio.h>
#include <string.h>
#include "../src/dns_response.h"

static int fails = 0;
#define CHECK(c) do { if (!(c)) { printf("FALHOU: %s (linha %d)\n", #c, __LINE__); fails++; } } while (0)

/* --- Pacote 1: unb.br MX -> mx.unb.br, preference 10 (do mapa). --- */
static const unsigned char ok_pkt[] = {
    0xAB,0xCD,0x81,0x80,0x00,0x01,0x00,0x01,0x00,0x00,0x00,0x00,
    0x03,'u','n','b',0x02,'b','r',0x00,0x00,0x0F,0x00,0x01,
    0xC0,0x0C,0x00,0x0F,0x00,0x01,0x00,0x00,0x01,0x2C,0x00,0x07,
    0x00,0x0A,0x02,'m','x',0xC0,0x0C
};

/* --- Pacote 2: dois MX (preference 20 e 10); deve escolher o de 10. --- */
static unsigned char two_mx_pkt[128];
static size_t two_mx_len;

static void build_two_mx_pkt(void)
{
    unsigned char *p = two_mx_pkt;
    size_t n = 0;

    /* header: id, flags, qd=1, an=2, ns=0, ar=0 */
    unsigned char hdr[] = {0x12,0x34,0x81,0x80,0x00,0x01,0x00,0x02,0x00,0x00,0x00,0x00};
    memcpy(p+n, hdr, sizeof hdr); n += sizeof hdr;

    /* question: unb.br MX IN (offset 12) */
    unsigned char q[] = {0x03,'u','n','b',0x02,'b','r',0x00,0x00,0x0F,0x00,0x01};
    memcpy(p+n, q, sizeof q); n += sizeof q; /* termina em offset 24 */

    /* RR1: nome=ponteiro(12), MX, IN, ttl, rdlen=10, pref=20, exchange="smtp2" + ponteiro(12) */
    unsigned char rr1[] = {
        0xC0,0x0C, 0x00,0x0F, 0x00,0x01, 0x00,0x00,0x00,0x3C,
        0x00,0x0A,
        0x00,0x14,                 /* preference 20 */
        0x05,'s','m','t','p','2', 0xC0,0x0C
    };
    memcpy(p+n, rr1, sizeof rr1); n += sizeof rr1;

    /* RR2: nome=ponteiro(12), MX, IN, ttl, rdlen=10, pref=10, exchange="smtp1" + ponteiro(12) */
    unsigned char rr2[] = {
        0xC0,0x0C, 0x00,0x0F, 0x00,0x01, 0x00,0x00,0x00,0x3C,
        0x00,0x0A,
        0x00,0x0A,                 /* preference 10 */
        0x05,'s','m','t','p','1', 0xC0,0x0C
    };
    memcpy(p+n, rr2, sizeof rr2); n += sizeof rr2;

    two_mx_len = n;
}

static dns_resp_status_t run_mx(const unsigned char *p, size_t n, uint16_t id, dns_mx_record_t *mx)
{
    return dns_parse_mx_response(p, n, id, mx);
}

int main(void)
{
    unsigned char p[sizeof ok_pkt];
    dns_response_header_t h;
    dns_mx_record_t mx;

    /* ---------- Leitura do header ---------- */
    CHECK(dns_parse_header(ok_pkt, sizeof ok_pkt, &h) == 0);
    CHECK(h.id == 0xABCD && h.qr == 1 && h.rcode == 0);
    CHECK(h.qdcount == 1 && h.ancount == 1);
    CHECK(dns_parse_header(ok_pkt, 11, &h) == -1);
    CHECK(dns_parse_header(NULL, 20, &h) == -1);

    /* ---------- Decodificação de nomes ---------- */
    {
        char name[DNS_MAX_NAME_LEN];
        size_t end;
        int n = dns_decode_name(ok_pkt, sizeof ok_pkt, 12, name, sizeof name, &end);
        CHECK(n > 0 && strcmp(name, "unb.br") == 0);
        CHECK(end == 20); /* logo após o 0x00 */

        /* nome com ponteiro no final: offset 38 ("mx" + C0 0C) */
        n = dns_decode_name(ok_pkt, sizeof ok_pkt, 38, name, sizeof name, &end);
        CHECK(n > 0 && strcmp(name, "mx.unb.br") == 0);
        CHECK(end == 43); /* 2 bytes após o ponteiro, não o fim do nome apontado */

        /* ponteiro para frente: inválido (anti-loop) */
        unsigned char fwd[] = { 0xC0, 0x02, 0x00 };
        CHECK(dns_decode_name(fwd, sizeof fwd, 0, name, sizeof name, &end) == -1);

        /* label que estoura o buffer */
        unsigned char trunc[] = { 0x05, 'a', 'b' };
        CHECK(dns_decode_name(trunc, sizeof trunc, 0, name, sizeof name, &end) == -1);

        /* offset inicial fora do buffer */
        CHECK(dns_decode_name(ok_pkt, sizeof ok_pkt, 1000, name, sizeof name, &end) == -1);

        /* buffer de saída pequeno demais */
        char tiny[3];
        CHECK(dns_decode_name(ok_pkt, sizeof ok_pkt, 12, tiny, sizeof tiny, &end) == -1);
    }

    /* ---------- Extração de MX: sucesso simples ---------- */
    memset(&mx, 0, sizeof mx);
    CHECK(run_mx(ok_pkt, sizeof ok_pkt, 0xABCD, &mx) == DNS_RESP_OK);
    CHECK(mx.preference == 10);
    CHECK(strcmp(mx.exchange, "mx.unb.br") == 0);

    /* ---------- Extração de MX: dois registros, escolhe o de menor preference ---------- */
    build_two_mx_pkt();
    memset(&mx, 0, sizeof mx);
    CHECK(run_mx(two_mx_pkt, two_mx_len, 0x1234, &mx) == DNS_RESP_OK);
    CHECK(mx.preference == 10);
    CHECK(strcmp(mx.exchange, "smtp1.unb.br") == 0);

    /* ---------- Casos de erro DNS ---------- */

    /* NXDOMAIN */
    memcpy(p, ok_pkt, sizeof p);
    p[3] = 0x83; p[7] = 0; /* RCODE=3, ancount=0 */
    CHECK(run_mx(p, 24, 0xABCD, &mx) == DNS_RESP_NXDOMAIN);

    /* sem MX: RCODE 0, ANCOUNT 0 */
    memcpy(p, ok_pkt, sizeof p);
    p[7] = 0;
    CHECK(run_mx(p, 24, 0xABCD, &mx) == DNS_RESP_NO_MX);

    /* sem MX: ANCOUNT 1 mas RR é do tipo A, não MX */
    {
        unsigned char only_a[] = {
            0x12,0x34,0x81,0x80,0x00,0x01,0x00,0x01,0x00,0x00,0x00,0x00,
            0x03,'u','n','b',0x02,'b','r',0x00,0x00,0x0F,0x00,0x01,
            0xC0,0x0C, 0x00,0x01, 0x00,0x01, 0x00,0x00,0x00,0x3C,
            0x00,0x04, 0x01,0x02,0x03,0x04
        };
        CHECK(run_mx(only_a, sizeof only_a, 0x1234, &mx) == DNS_RESP_NO_MX);
    }

    /* ID diferente do esperado */
    CHECK(run_mx(ok_pkt, sizeof ok_pkt, 0x0000, &mx) == DNS_RESP_INVALID);

    /* SERVFAIL (2) */
    memcpy(p, ok_pkt, sizeof p); p[3] = 0x82;
    CHECK(run_mx(p, sizeof p, 0xABCD, &mx) == DNS_RESP_INVALID);

    /* TC = 1 (truncada) */
    memcpy(p, ok_pkt, sizeof p); p[2] = 0x83;
    CHECK(run_mx(p, sizeof p, 0xABCD, &mx) == DNS_RESP_INVALID);

    /* RDLENGTH que estoura o datagrama */
    {
        unsigned char bad_rdlen[] = {
            0x12,0x34,0x81,0x80,0x00,0x01,0x00,0x01,0x00,0x00,0x00,0x00,
            0x03,'u','n','b',0x02,'b','r',0x00,0x00,0x0F,0x00,0x01,
            0xC0,0x0C, 0x00,0x0F, 0x00,0x01, 0x00,0x00,0x00,0x3C,
            0xFF,0xFF, /* RDLENGTH absurdo */
            0x00,0x0A
        };
        CHECK(run_mx(bad_rdlen, sizeof bad_rdlen, 0x1234, &mx) == DNS_RESP_INVALID);
    }

    puts(fails ? "Testes com falha." : "Todos os testes passaram.");
    return fails != 0;
}