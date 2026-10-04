# SONOORA UUID

<!-- sonoora-architecture:active -->
> [Arquitetura vigente](../../../current_memory/core/ARQUITETURA_REPOS_E_OPERACAO.md): API executa Circle e mantém financeiro, integrações e auditoria; UUID autentica e fornece ciphertext contextual.

## Contrato implementado

`POST /internal/v1/ciphertext`, JSON estrito (16 KiB), `X-API-Key` DEV/PROD. Identidade vem da chave validada, nunca de Origin/IP/body. Contexto inclui operação, tentativa, finalidade, ator, vínculo de negócio e comando Circle completo. Retorna `idempotencyKey`, `entitySecretCiphertext` fresco e `audit` com IDs e hashes RFC 8785 / SHA-256. Não aceita comando arbitrário: somente wallet.create, wallet.deploy e token.transfer.

O journal confirma a gravação antes da resposta. Repetir requestId é conflito; um novo pedido da mesma operação conserva a chave Circle e não pode alterar contexto. `GET /internal/v1/ciphertext/requests/{requestId}` consulta somente recibo do próprio caller. Nunca recupera ciphertext. `GET /generate` retorna 410; não há fallback legado. `/health` comprova apenas liveness.

Hashes permitem correlação e detecção de divergência. Não são assinatura independente nem restringem criptograficamente o ciphertext a um comando na Circle. A API continua responsável pela autorização financeira, despacho exato, idempotência e resultado.

## Configuração e migração

Ver `.env.example`. Preservar ENTITY_SECRET e PUBLIC_KEY existentes; UUID não usa CIRCLE_API_KEY. API_KEY_DEV e API_KEY_PROD são distintos, 64 caracteres hex minúsculos. UUID_POLICY_DEV/PROD define accountRef, blockchains, walletSetIds, tokenAddresses e version. UUID_ISSUANCE_ENABLED=true habilita emissão somente quando os demais controles passam.

Aplicar migrations/001_context_journal.sql com o dono de migração nos bancos existentes. Runtime conecta por TLS com logins diferentes que pertencem exclusivamente a sonoora_uuid_dev ou sonoora_uuid_prod; nunca dono/superuser nem membro do dono. Grupos são NOLOGIN; criar/provisionar logins por gestão de segredos, não no repositório. Runtime recebe somente EXECUTE nas funções, sem UPDATE/DELETE/SELECT direto. Leitor de auditoria recebe grupo sonoora_uuid_audit_reader conforme necessidade. Não dar esse grupo ao runtime UUID. Quota transacional: 30 emissões/minuto/caller; limite inicial a validar com carga antes do corte.

Não promover isoladamente: migrar journal/API, configurar chaves/políticas e preparar todos os callers antes de trocar o único projeto UUID. Nenhuma nova configuração ou ativação foi executada apenas por este código. Callbacks legados são uma integração distinta e não foram adicionados ao contrato contextual.

## Validação

`python -m unittest discover -s tests -v`. Para prova PostgreSQL: UUID_TEST_DATABASE_URL deve apontar a banco local dedicado cujo nome contém fixture; esses testes criam roles e truncam somente uuid_audit desse banco. Nunca executar com URL real. Ver [execução H](../../../current_memory/Review%20and%20Fixes/01_plans/20261003_uuid_restore_contextual_helper/HELPER_EXECUTION.md) para candidato, resultados, push e pendências de corte. O rollback publicado continua documentado separadamente em ROLLBACK_EXECUTION.md.
