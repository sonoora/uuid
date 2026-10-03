# SONOORA UUID

<!-- sonoora-architecture:active -->
> [Arquitetura vigente](../../../current_memory/core/ARQUITETURA_REPOS_E_OPERACAO.md): API executa Circle e mantém financeiro, integrações e auditoria; UUID fornece ciphertext. HOME, PASS, ADMIN, API, PAY e UUID são os repos de destino.

Helper Circle FastAPI. Autentica `X-API-Key` com `API_KEY`, gera ciphertext usando `ENTITY_SECRET` e `PUBLIC_KEY`, e devolve `idempotencyKey` e `entitySecretCiphertext`. A API executa o comando Circle com sua própria `CIRCLE_API_KEY`; essa credencial não é necessária no UUID.

## Runtime e configuração

- Vercel: projeto único `uuid`, branch `main`, entrada `app:app` / `main:app`.
- `GET /health`: liveness; não comprova integração autenticada.
- `GET /generate`: helper anterior, com autenticação e controles existentes.
- Configuração existente: `API_KEY`, `ENTITY_SECRET`, `PUBLIC_KEY`; não imprimir valores. `SESSION_SECRET` existente não é removida por suposição.
- Nenhum endpoint executor, claim/report ou credencial Circle de execução é requerido.

## Restauração de 2026-10-03

Código funcional restaurado ao baseline `27e41e88adb1acb40ec7e899be1c1460d53916fe`, em correção rastreável do lote executor. Sem nova arquitetura, conta Circle ou migração de dados. Ver [changelog](CHANGELOG.md) e [relatório de execução](../../../current_memory/Review%20and%20Fixes/01_plans/20261003_uuid_restore_contextual_helper/ROLLBACK_EXECUTION.md) para testes, publicação e limites reais.

Chaves distintas DEV/PROD e auditoria contextual são evolução futura, ainda não implementada por este rollback. Não reativar o executor removido a partir de documentação histórica.
