# SONOORA UUID

<!-- sonoora-architecture:active -->
> **Arquitetura vigente:** [mapa de repos e responsabilidades](<../../../current_memory/core/ARQUITETURA_REPOS_E_OPERACAO.md>). Destino HOME/PASS/ADMIN/API/PAY/UUID; Financeiro, integrações/orquestração e auditoria são responsabilidades internas da API. CORE e SCOUT são nomes históricos aposentados; AUDIT é auditoria da API, sem componente independente no desenho vigente. UUID permanece separado e comum aos consumidores desde o início. Esses nomes não exigem repos/bancos novos; destino não comprova migração/implementação.


FastAPI Circle executor with signed service identity, a persisted API dispatch permit and a fixed operation allowlist. Legacy helper mode remains available only before the coordinated cutover.

## Runtime

- Framework: FastAPI
- Runtime entrypoint: `main:app`
- Vercel entrypoint: `app:app`
- Vercel project: `uuid`
- Legacy env names: `API_KEY`, `ENTITY_SECRET`, `PUBLIC_KEY`. Executor configuration is listed below.

Do not commit real secret values. Configure the env names in Vercel as sensitive project variables.

## Routes

- `GET /health`: process liveness only; does not prove database, credential or provider readiness.
- `GET /generate`: legacy-only; returns HTTP 410 in executor/paused mode.
- `POST /internal/v1/operations/{operationId}/execute`: signed service request with `{schemaVersion:1}`; accepts no economic fields or provider URL from the caller.

## Local

```powershell
python -m venv .venv
.\.venv\Scripts\python -m pip install -r requirements.txt
$env:API_KEY='local-only'
$env:ENTITY_SECRET='64_hex_chars_here'
$env:PUBLIC_KEY='pem_public_key_here'
.\.venv\Scripts\python -m uvicorn main:app --host 127.0.0.1 --port 5000
```

## Common executor configuration

`CIRCLE_EXECUTION_MODE` is `legacy` (compatibility default), `executor`, or `paused`. Change API/ADMIN/workers/UUID together; never enable a product-specific bypass. Pausing disables new execution while API result reporting and reconciliation remain available. Returning to legacy is not a safe rollback after activation.

| Name | Meaning |
| --- | --- |
| CIRCLE_EXECUTION_ENVIRONMENT | local/staging/production; equal to API ONBOARDING_APP_ENV |
| CIRCLE_EXECUTION_ACCOUNT_REF | Explicit account binding, equal to API; verify actual Circle credentials |
| CIRCLE_EXECUTION_AUTHORITY_URL | Exact HTTPS API origin, without path, query or credentials |
| CIRCLE_EXECUTION_SIGNING_KEY | UUID private RSA key, minimum 2048 bits; server only |
| CIRCLE_EXECUTION_KEY_ID | Active signing key identifier |
| CIRCLE_API_PUBLIC_KEYS | JSON object mapping API key IDs to public PEM keys; remove a key to revoke it |
| CIRCLE_API_KEY | Circle credential confined to the executor in the target deployment |
| ENTITY_SECRET / PUBLIC_KEY | Existing Circle Entity Secret and encryption public key |
| CIRCLE_USDC_TOKEN_ADDRESS_MATIC | Exact allowed token contract |
| CIRCLE_EXECUTION_BLOCKCHAIN | MATIC for this compatibility cut; must agree with API |
| CIRCLE_WALLET_SET_ID | Exact allowed wallet set |

Tokens are RS256, valid for 60 seconds and bound to method, path, body digest, environment, issuer, audience and scope. Private service keys differ between API and UUID and between environments. Ciphertext is generated internally and never returned to API. HTTP transport follows no redirects and does not retry provider POSTs. Unknown results retain the original dispatch permit and require reconciliation.

Wallet creation, zero-amount SCA deployment and USDC transfer are the only mutations. API owns business authorization, source reservation and ledger. The source reservation survives uncertainty; balance verification occurs before provider submission.

## Verification and activation

Install `requirements-test.txt` in a local virtual environment; run `python -m unittest discover -s tests -v`. API cross-runtime tests accept `UUID_TEST_PYTHON` or locate the sibling UUID virtual environment. Fixtures generate synthetic keys and simulate provider effects.

[Implementation and review](../../../current_memory/Review%20and%20Fixes/01_plans/20261003_uuid_common_execution/EXECUTION.md). No deployment or credential activation is implied. Before enabling executor mode, classify old intents/wallet attempts, retire old writers/aliases and verify provider account/permissions. `/health` alone never approves activation.
