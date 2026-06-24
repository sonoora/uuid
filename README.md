# SONOORA UUID

FastAPI helper for generating Circle-compatible entity secret ciphertext.

## Runtime

- Framework: FastAPI
- Entrypoint: `main:app`
- Vercel project: `uuid`
- Required env names: `API_KEY`, `ENTITY_SECRET`, `PUBLIC_KEY`, `SESSION_SECRET`

Do not commit real secret values. Configure the env names in Vercel as sensitive project variables.

## Routes

- `GET /health`: readiness check.
- `GET /generate`: requires `X-API-Key` and returns `idempotencyKey` plus `entitySecretCiphertext`.

## Local

```powershell
python -m venv .venv
.\.venv\Scripts\python -m pip install -e .
$env:API_KEY='local-only'
$env:ENTITY_SECRET='64_hex_chars_here'
$env:PUBLIC_KEY='pem_public_key_here'
.\.venv\Scripts\python -m uvicorn main:app --host 127.0.0.1 --port 5000
```
