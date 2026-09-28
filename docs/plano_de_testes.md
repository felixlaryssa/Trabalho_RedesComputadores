# Plano de Testes - Cliente DNS MX

Este documento descreve a matriz de testes para validação dos requisitos do Trabalho 01.

| Cenário | Comando de Exemplo | Resultado Esperado | Responsável | Status |
|---------|--------------------|--------------------|-------------|--------|
| **MX existente** | `./meu_cliente unb.br 8.8.8.8` | Formato: `unb.br <> servidor_email` | Pessoa 4 | Pendente |
| **Domínio inexistente** | `./meu_cliente asdasd.com 1.1.1.1` | Mensagem: `Dominio... nao encontrado` (NXDOMAIN) | Pessoa 4 | Pendente |
| **Sem registro MX** | `./meu_cliente fga.unb.br 8.8.8.8` | Mensagem: `Dominio... nao possui entrada MX` | Pessoa 4 | Pendente |
| **DNS sem resposta** | `./meu_cliente unb.br 1.2.3.4` | Mensagem de falha após no máximo 3 tentativas de timeout (2s) | Pessoa 4 | Pendente |
| **IP inválido** | `./meu_cliente unb.br abc` | Erro controlado informado ao usuário, sem crash do programa | Pessoa 4 | Pendente |
| **Argumentos faltando** | `./meu_cliente unb.br` | Mensagem de uso: `Uso: ./meu_cliente <dominio> <servidor_dns>` | Pessoa 4 | Pendente |