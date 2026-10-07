# Changelog UUID

<!-- sonoora-architecture:active -->
> [Arquitetura vigente](../../../current_memory/core/ARQUITETURA_REPOS_E_OPERACAO.md): API executa Circle e mantém financeiro, integrações e auditoria; UUID fornece ciphertext. HOME, PASS, ADMIN, API, PAY e UUID são os repos de destino.

## 2026-10-07 — bounded contextual emission capacity

Migration003 and native PostgreSQL concurrency/adversarial tests add shared global/purpose/subject burst/minute admission, atomic rollback, immutable reuse and restricted runtime policy access. Crypto/API contract unchanged. Explicit per-database DEV activation; PROD requires separate rollout. Internal ceilings require traffic/provider calibration. Git/schema/runtime proofs are recorded in the root capacity plan section15; UUID executes no Circle transaction.
## 2026-10-04 — ativação contextual publicada

Estado confirmado: helper contextual ativo em UUID/main 917b133, API/dev 3d5ff84 e API/prod bffcec9, com deployments Git READY e aliases conferidos. Schemas e logins restritos DEV/PROD aplicados; emissão, hashes, recibo, retry, isolamento e readiness comprovados. API conserva execução Circle; callback e credenciais Circle preservados. PUBLIC_KEY mantém normalização compatível com a configuração anterior.

Esta entrada documental não altera código/configuração. H5 técnico concluído; homologação financeira ponta a ponta (H6) permanece com PASS v1, sem movimentação de teste neste lote. Entradas inferiores são fotografias históricas, inclusive as que registravam corte pendente e o candidato amplo posteriormente retirado. Fonte: current_memory/Review and Fixes/01_plans/20261003_uuid_restore_contextual_helper/SCOPE_EXECUTION.md, no root SONOORA; eventos em HISTORY.jsonl e changelog central.

## 2026-10-04 — correção do escopo contextual

Supera o candidato amplo descrito abaixo: API mantém seu fluxo/controles Circle e só acrescenta contexto/recibo ao helper. UUID autentica DEV/PROD e registra emissão; mesma chave efetiva, ciphertext novo. Retiradas nova orquestração, reservas/locks/dispatch e UI ADMIN. Testes locais e revisão própria; sem novo monólito. [Execução reduzida e limites](../../../current_memory/Review%20and%20Fixes/01_plans/20261003_uuid_restore_contextual_helper/SCOPE_EXECUTION.md). Runtime/configuração/corte continuam separados e pendentes.

## 2026-10-04 — helper UUID contextual

API executa Circle; UUID autentica DEV/PROD, grava contexto e retorna ciphertext/recibo. Intenções não armazenam ciphertext novo; despacho tem marcador durável, confirmação de lease e recuperação sem replay automático. ADMIN usa leitura de evidência protegida e deixa de buscar material para remediação. Validação local e eventos de commit/push em [execução H](../../../current_memory/Review%20and%20Fixes/01_plans/20261003_uuid_restore_contextual_helper/HELPER_EXECUTION.md). Corte de runtime/configuração não realizado por este candidato.


## 2026-10-03 — restore Circle helper

Remove o executor introduzido em `3d36cd2` e restaura os arquivos funcionais do helper `27e41e8`. API volta a ser o único emissor de comandos Circle neste contrato. Credenciais originais preservadas; contexto/identidades novas ficam para outro lote.

Provas e marcos de commit/push/deploy: [relatório único](../../../current_memory/Review%20and%20Fixes/01_plans/20261003_uuid_restore_contextual_helper/ROLLBACK_EXECUTION.md). Existência desta entrada não comprova publicação.

## 2026-10-04 — Activation diagnostics

Record only failure stage/type for crypto and unexpected request failures, without exception text, payloads or credentials. Staged live issuance failed before receipt; no production-domain promotion. 15 unit tests pass; six database fixture tests skipped in this focused run.

## 2026-10-04 — Public key configuration compatibility

Restore the deployed helper's PUBLIC_KEY normalization before RSA import, retaining existing secret/key variables and crypto validation. Live staged diagnostics isolated failure to public-key parsing. Added synthetic encryption/decryption tests for five legacy formats; 16 unit tests pass, six database fixture tests skipped in focused run. Domain cut remains pending live verification.
