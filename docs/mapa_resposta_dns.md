# Mapa da resposta DNS (consulta MX / IN)

Documento de apoio ao parser (`dns_response.c/.h`). 

Todos os **offsets** abaixo são contados a partir do **início do datagrama UDP**
(byte 0 = primeiro byte do Transaction ID).

## 1. Visão geral da mensagem

```
+---------------------------+
| Header            (12 B)  |  tamanho fixo
+---------------------------+
| Question          (var.)  |  QDCOUNT entradas (aqui: 1) - eco da pergunta
+---------------------------+
| Answer            (var.)  |  ANCOUNT registros (RRs)
+---------------------------+
| Authority         (var.)  |  NSCOUNT RRs (ex.: SOA em "sem MX")
+---------------------------+
| Additional        (var.)  |  ARCOUNT RRs (ex.: IPs dos MX)
+---------------------------+
```

Para este trabalho só precisamos percorrer **Header → Question → Answer**.
Authority e Additional podem ser ignoradas.

## 2. Header (offsets 0 a 11)

| Offset | Tamanho | Campo   | Descrição |
|-------:|:-------:|---------|-----------|
| 0-1    | 2 B     | ID      | Deve ser igual ao Transaction ID enviado na consulta |
| 2-3    | 2 B     | FLAGS   | Ver detalhamento abaixo |
| 4-5    | 2 B     | QDCOUNT | Nº de perguntas (esperado: 1) |
| 6-7    | 2 B     | ANCOUNT | Nº de RRs na seção Answer |
| 8-9    | 2 B     | NSCOUNT | Nº de RRs na seção Authority |
| 10-11  | 2 B     | ARCOUNT | Nº de RRs na seção Additional |

### FLAGS (16 bits, bit 15 = mais significativo)

```
 15  14 13 12 11  10  9   8   7   6 5 4   3 2 1 0
+---+-----------+----+----+----+----+-----+--------+
|QR |  OPCODE   | AA | TC | RD | RA |  Z  | RCODE  |
+---+-----------+----+----+----+----+-----+--------+
```

| Campo  | Máscara  | Significado |
|--------|----------|-------------|
| QR     | `0x8000` | 0 = consulta, **1 = resposta** (deve ser 1) |
| OPCODE | `0x7800` | 0 = consulta padrão |
| AA     | `0x0400` | Resposta autoritativa |
| TC     | `0x0200` | **Truncada** (não coube em 512 B UDP) |
| RD     | `0x0100` | Recursão desejada (copiada da consulta) |
| RA     | `0x0080` | Recursão disponível no servidor |
| Z      | `0x0070` | Reservado |
| RCODE  | `0x000F` | **Código de resposta** (tabela abaixo) |

Extração: `rcode = flags & 0x000F;` e `is_response = (flags & 0x8000) != 0;`

### RCODE

| Valor | Nome     | Interpretação no trabalho |
|:-----:|----------|---------------------------|
| 0     | NOERROR  | Consulta ok; ver ANCOUNT (0 = domínio existe mas **sem MX**) |
| 1     | FORMERR  | Consulta malformada (erro genérico) |
| 2     | SERVFAIL | Falha no servidor (erro genérico) |
| 3     | NXDOMAIN | **Domínio inexistente** |
| 4     | NOTIMP   | Não implementado (erro genérico) |
| 5     | REFUSED  | Recusado (erro genérico) |

## 3. Question (começa no offset 12)

| Campo  | Tamanho  | Descrição |
|--------|:--------:|-----------|
| QNAME  | variável | Nome em labels (`03 unb 02 br 00`), termina em byte `0x00` |
| QTYPE  | 2 B      | 15 (MX) |
| QCLASS | 2 B      | 1 (IN) |

Como QNAME tem tamanho variável, o parser precisa **percorrer os labels até o
`0x00`** para saber onde a Question termina. Em geral não há ponteiro de
compressão na Question. Depois do `0x00` avance 4 bytes (QTYPE + QCLASS). Esse é o início da Answer.

## 4. Resource Record (RR) - formato de cada entrada de Answer/Authority/Additional

| Campo    | Tamanho  | Descrição |
|----------|:--------:|-----------|
| NAME     | variável | Nome dono do registro: labels, **ponteiro (2 B)** ou labels + ponteiro |
| TYPE     | 2 B      | Tipo do registro (ver tabela) |
| CLASS    | 2 B      | 1 = IN |
| TTL      | 4 B      | Tempo de vida em segundos (`uint32_t`) |
| RDLENGTH | 2 B      | Tamanho em bytes do RDATA |
| RDATA    | RDLENGTH | Dados; formato depende do TYPE |

| TYPE | Nome  | Ação do parser |
|:----:|-------|----------------|
| 1    | A     | ignorar (avançar RDLENGTH) |
| 2    | NS    | ignorar |
| 5    | CNAME | ignorar |
| 6    | SOA   | ignorar |
| 15   | **MX**| **extrair** |
| 28   | AAAA  | ignorar |

**Regra:** para qualquer RR, depois de ler NAME/TYPE/CLASS/TTL/RDLENGTH,
o próximo RR começa em `início_do_RDATA + RDLENGTH`, independentemente do tipo.
Isso é o que permite pular RRs que não interessam.

### RDATA do tipo MX

| Campo      | Tamanho  | Descrição |
|------------|:--------:|-----------|
| PREFERENCE | 2 B      | Prioridade (menor = preferido) |
| EXCHANGE   | variável | Nome do servidor de e-mail (**pode usar compressão**) |

## 5. Compressão de nomes

Cada byte de tamanho em um nome pode ser:

| Bits mais altos do byte | Significado |
|-------------------------|-------------|
| `00xxxxxx` (0x00-0x3F)  | Label de `xxxxxx` bytes; `0x00` encerra o nome |
| `11xxxxxx` (0xC0-0xFF)  | **Ponteiro**: 2 bytes; offset = `((b0 & 0x3F) << 8) \| b1`, contado desde o início do datagrama |
| `01` / `10`             | Reservado: tratar como erro |

Regras para o decodificador:

1. Ao encontrar um ponteiro, **salte** para o offset e continue lendo labels.
2. A posição de retorno do chamador avança apenas **2 bytes** (o ponteiro), e
   só na **primeira** vez que um ponteiro é seguido. Guarde essa posição.
3. Um ponteiro encerra o nome (não há `0x00` depois dele).
4. Exemplo: `02 6D 78 C0 0C` = label "mx" + ponteiro para o offset 12 (`unb.br`) = `mx.unb.br`.
5. Proteções obrigatórias: limite de saltos (ex.: 16) contra loops; offset
   sempre `< tamanho recebido`; label sem ultrapassar o fim do buffer; nome
   final até 255 bytes; buffer de saída sem estouro.

## 6. Exemplo byte a byte (ilustrativo)

Resposta **fictícia** para `unb.br` MX, com MX `mx.unb.br` (preference 10, TTL
300). O ID `ABCD` é arbitrário. 

```
Offset  Bytes                      Campo
------  -------------------------  ---------------------------------------
 0-1    AB CD                      ID = 0xABCD
 2-3    81 80                      FLAGS: QR=1 RD=1 RA=1 RCODE=0
 4-5    00 01                      QDCOUNT = 1
 6-7    00 01                      ANCOUNT = 1
 8-9    00 00                      NSCOUNT = 0
10-11   00 00                      ARCOUNT = 0
--- Question ---
12      03                         label de 3 bytes
13-15   75 6E 62                   "unb"
16      02                         label de 2 bytes
17-18   62 72                      "br"
19      00                         fim do nome
20-21   00 0F                      QTYPE = 15 (MX)
22-23   00 01                      QCLASS = 1 (IN)
--- Answer RR #1 (começa no offset 24) ---
24-25   C0 0C                      NAME = ponteiro -> offset 12 ("unb.br")
26-27   00 0F                      TYPE = 15 (MX)
28-29   00 01                      CLASS = 1 (IN)
30-33   00 00 01 2C                TTL = 300
34-35   00 07                      RDLENGTH = 7
36-37   00 0A                      PREFERENCE = 10
38      02                         label de 2 bytes
39-40   6D 78                      "mx"
41-42   C0 0C                      ponteiro -> offset 12 ("unb.br")
                                   => EXCHANGE = "mx.unb.br"
Total: 43 bytes. Próximo RR (se houvesse) começaria em 36 + 7 = 43.
```

## 7. Fluxo sugerido para o parser

```
1. len >= 12?                                   senão -> RESPOSTA_INVALIDA
2. ID == transaction_id enviado?                senão -> ignorar/inválida
3. QR == 1?                                     senão -> inválida
4. TC == 1?                                     -> tratar como inválida/truncada
5. RCODE == 3?                                  -> DOMINIO_INEXISTENTE
   RCODE != 0?                                  -> RESPOSTA_INVALIDA (erro do servidor)
6. Pular Question: QDCOUNT vezes (decodificar nome + 4 bytes)
7. ANCOUNT == 0?                                -> SEM_MX
8. Para cada RR da Answer (com checagem de limites):
     decodificar NAME; ler TYPE, CLASS, TTL, RDLENGTH;
     garantir offset + RDLENGTH <= len
     se TYPE == 15 e CLASS == 1:
         ler PREFERENCE; decodificar EXCHANGE (dentro do RDATA)
         guardar (escolher menor preference)
     avançar para início_do_RDATA + RDLENGTH
9. Encontrou algum MX?                          -> SUCESSO; senão -> SEM_MX
```

## 8. Como obter respostas reais para conferir

```
dig @8.8.8.8 unb.br MX +noall +answer
dig @8.8.8.8 unb.br MX +norecurse +qr        # mostra também a consulta
dig @1.1.1.1 dominioqueNaoexiste123.com MX   # NXDOMAIN
dig @8.8.8.8 fga.unb.br MX                   # NOERROR sem MX (a confirmar)
```

No Wireshark, filtro `dns && udp.port == 53`, selecione a resposta e use
*Copy > ...as Hex Stream* na camada DNS para gerar um vetor de teste em C.
Compare offsets do Wireshark ("Bytes" pane) com as tabelas acima.