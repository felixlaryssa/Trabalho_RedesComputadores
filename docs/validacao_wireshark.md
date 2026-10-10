# Validação de Requisição DNS (Wireshark e dig)

## 1. Comparação com o utilitário `dig`
Comando executado para obter o baseline esperado:
\`\`\`bash
dig MX unb.br @8.8.8.8
\`\`\`
*(Adicionar aqui a saída do comando dig demonstrando o servidor de e-mail esperado)*

## 2. Captura no Wireshark do `meu_cliente`
Filtro utilizado no Wireshark para isolar a comunicação: `udp.port == 53 && dns`

Comando executado no nosso cliente:
\`\`\`bash
./meu_cliente unb.br 8.8.8.8
\`\`\`

### Evidências Confirmadas:
- [ ] **Destino UDP/53:** O pacote é enviado via protocolo UDP com porta de destino 53.
- [ ] **QTYPE MX:** O campo Type da Query está definido como `MX (15)`.
- [ ] **QCLASS IN:** O campo Class da Query está definido como `IN (1)`.

*(Adicionar aqui o print da tela do Wireshark com as setas apontando para as flags QTYPE MX e QCLASS IN no datagrama gerado pelo nosso código)*