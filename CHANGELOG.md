# Changelog UUID

<!-- sonoora-architecture:active -->
> [Arquitetura vigente](../../../current_memory/core/ARQUITETURA_REPOS_E_OPERACAO.md): API executa Circle e mantém financeiro, integrações e auditoria; UUID fornece ciphertext. HOME, PASS, ADMIN, API, PAY e UUID são os repos de destino.

## 2026-10-03 — restore Circle helper

Remove o executor introduzido em `3d36cd2` e restaura os arquivos funcionais do helper `27e41e8`. API volta a ser o único emissor de comandos Circle neste contrato. Credenciais originais preservadas; contexto/identidades novas ficam para outro lote.

Provas e marcos de commit/push/deploy: [relatório único](../../../current_memory/Review%20and%20Fixes/01_plans/20261003_uuid_restore_contextual_helper/ROLLBACK_EXECUTION.md). Existência desta entrada não comprova publicação.
