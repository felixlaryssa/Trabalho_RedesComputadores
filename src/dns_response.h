#ifndef DNS_RESPONSE_H
#define DNS_RESPONSE_H

#include <stddef.h>
#include <stdint.h>

#define DNS_RESP_HEADER_SIZE 12

/* Máscaras do campo FLAGS (ver docs/mapa_resposta_dns.md). */
#define DNS_FLAG_QR     0x8000u
#define DNS_FLAG_OPCODE 0x7800u
#define DNS_FLAG_AA     0x0400u
#define DNS_FLAG_TC     0x0200u
#define DNS_FLAG_RD     0x0100u
#define DNS_FLAG_RA     0x0080u
#define DNS_FLAG_RCODE  0x000Fu

/* Valores de RCODE relevantes. */
#define DNS_RCODE_NOERROR  0
#define DNS_RCODE_NXDOMAIN 3

/* Tipos/classe usados na leitura das respostas. */
#define DNS_RTYPE_MX  15
#define DNS_RCLASS_IN 1

/* Menor tamanho possível de uma Question / de um RR (nome = só o byte 0x00). */
#define DNS_MIN_QUESTION_SIZE 5   /* 1 (nome) + 2 (QTYPE) + 2 (QCLASS)          */
#define DNS_MIN_RR_SIZE       11  /* 1 (nome) + 2 + 2 + 4 (TTL) + 2 (RDLENGTH)  */

/* Nome DNS decodificado: até 255 bytes + ponto final + '\0'. */
#define DNS_MAX_NAME_LEN 256

/* Limite de saltos de compressão seguidos ao decodificar um nome (anti-loop). */
#define DNS_MAX_NAME_POINTER_JUMPS 16

/* Estados da resposta (usados pelo main para escolher a mensagem). */
typedef enum {
    DNS_RESP_OK = 0,     /* pelo menos um registro MX foi extraído            */
    DNS_RESP_NXDOMAIN,   /* RCODE 3: domínio inexistente                      */
    DNS_RESP_NO_MX,      /* RCODE 0, mas nenhuma entrada MX na resposta       */
    DNS_RESP_INVALID     /* malformada, ID errado, truncada, RCODE de erro,
                             nome com ponteiro inválido/loop, buffer curto... */
} dns_resp_status_t;

/* Header já convertido para a ordem de bytes do host. */
typedef struct {
    uint16_t id;
    uint16_t flags;    /* valor bruto de FLAGS                                */
    uint8_t  qr;       /* 1 = resposta                                        */
    uint8_t  opcode;
    uint8_t  aa;
    uint8_t  tc;
    uint8_t  rd;
    uint8_t  ra;
    uint8_t  rcode;
    uint16_t qdcount;
    uint16_t ancount;
    uint16_t nscount;
    uint16_t arcount;
} dns_response_header_t;

/* Um registro MX já decodificado. */
typedef struct {
    uint16_t preference;
    char     exchange[DNS_MAX_NAME_LEN]; /* nome do servidor, com pontos, ex: "mx.unb.br" */
} dns_mx_record_t;

/*
 * Lê os 12 bytes iniciais de `buffer` e preenche `header`.
 * Só verifica tamanho (len >= 12) e ponteiros nulos; não julga o conteúdo.
 *
 * Retorna 0 em sucesso, -1 se os argumentos forem inválidos ou o
 * datagrama for menor que o header.
 */
int dns_parse_header(
    const unsigned char *buffer,
    size_t len,
    dns_response_header_t *header
);

/*
 * Valida o header de uma resposta recebida (len = bytes recebidos).
 *
 * Retorna:
 *   DNS_RESP_INVALID   - ID diferente do esperado, QR != 1, OPCODE != 0,
 *                        TC = 1, QDCOUNT != 1, RCODE de erro (!= 0 e != 3)
 *                        ou contadores incompatíveis com o tamanho recebido;
 *   DNS_RESP_NXDOMAIN  - RCODE = 3;
 *   DNS_RESP_NO_MX     - RCODE = 0 e ANCOUNT = 0;
 *   DNS_RESP_OK        - header coerente com ANCOUNT > 0: siga para a
 *                        leitura da Question e das Answers.
 */
dns_resp_status_t dns_check_header(
    const dns_response_header_t *header,
    size_t len,
    uint16_t expected_id
);

/*
 * Decodifica um nome DNS (labels e/ou ponteiros de compressão) que começa
 * em `buffer[start_offset]`. `buffer`/`len` são o datagrama inteiro, pois
 * ponteiros podem apontar para qualquer offset anterior.
 *
 * `out` recebe o nome em texto, com pontos entre labels, sem o ponto
 * final e terminado em '\0' (ex.: "mx.unb.br"); `out_size` é o tamanho
 * do buffer de saída (recomendado: DNS_MAX_NAME_LEN).
 *
 * `end_offset`, se não for NULL, recebe o offset logo após o fim do nome
 * **na posição original** (ou seja, após o primeiro ponteiro seguido, ou
 * após o 0x00 se não houve ponteiro). É o valor que o chamador deve usar
 * para continuar lendo os campos seguintes (TYPE, CLASS, ...).
 *
 * Retorna o número de bytes escritos em `out` (sem contar o '\0'), ou -1
 * em caso de erro: offset inicial fora do buffer, label ultrapassando o
 * fim do buffer, ponteiro apontando para fora do buffer, excesso de
 * saltos (possível loop), nome maior que DNS_MAX_NAME_LEN, ou `out`
 * pequeno demais.
 */
int dns_decode_name(
    const unsigned char *buffer,
    size_t len,
    size_t start_offset,
    char *out,
    size_t out_size,
    size_t *end_offset
);

/*
 * Interpreta a resposta completa (Header + Question + Answers) e extrai o
 * registro MX de menor PREFERENCE.
 *
 * `buffer`/`len`      - datagrama recebido via recvfrom.
 * `expected_id`       - Transaction ID enviado na consulta.
 * `mx_out`            - preenchido com o MX de menor preference quando o
 *                        retorno é DNS_RESP_OK; não é tocado nos demais casos.
 *
 * Retorna o mesmo conjunto de estados de dns_check_header, com
 * DNS_RESP_OK significando "mx_out contém um MX válido". Qualquer
 * inconsistência estrutural encontrada ao percorrer Question/Answers
 * (nome malformado, RR cortado, RDLENGTH que estoura o buffer) também
 * resulta em DNS_RESP_INVALID.
 */
dns_resp_status_t dns_parse_mx_response(
    const unsigned char *buffer,
    size_t len,
    uint16_t expected_id,
    dns_mx_record_t *mx_out
);

#endif