# Cliente DNS MX - Trabalho 01

Este projeto implementa um cliente DNS em C que realiza consultas do tipo MX (Mail Exchange) da classe IN diretamente via UDP na porta 53, montando o datagrama e analisando os offsets das respostas sem a utilização de bibliotecas externas prontas.

## Ambiente e Compilação
- **Ambiente Testado:** Rocky Linux / distribuições Linux.
- **Compilador e Flags:** GCC (`-Wall -Wextra -Wpedantic`).
- **Validação de Memória:** Valgrind.

Para gerar o binário:
\`\`\`bash
make
\`\`\`
Para limpar artefatos de compilação:
\`\`\`bash
make clean
\`\`\`

## Execução e Exemplos
Sintaxe: `./meu_cliente <dominio> <servidor_dns>`

**1. Domínio com MX existente:**
\`\`\`bash
./meu_cliente unb.br 8.8.8.8
unb.br <> aspmx.l.google.com
\`\`\`

**2. Domínio Inexistente:**
\`\`\`bash
./meu_cliente asdasdasd.com 8.8.8.8
Dominio asdasdasd.com nao encontrado
\`\`\`

**3. Domínio sem entrada MX:**
\`\`\`bash
./meu_cliente fga.unb.br 8.8.8.8
Dominio fga.unb.br nao possui entrada MX
\`\`\`

**4. Timeout (Servidor DNS sem resposta):**
\`\`\`bash
./meu_cliente unb.br 1.2.3.4
Falha apos ate 3 tentativas
\`\`\`

## Limitações Conhecidas
- Suporte exclusivo para consultas de classe IN (1) e tipo MX (15).
- Requer endereço de DNS no formato IPv4 numérico.