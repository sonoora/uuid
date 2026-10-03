import os
import logging
import base64
import binascii
from datetime import datetime
from uuid import uuid4

from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.exceptions import RequestValidationError
from starlette.exceptions import HTTPException as StarletteHTTPException

from slowapi import Limiter
from slowapi.errors import RateLimitExceeded
from slowapi.middleware import SlowAPIMiddleware

from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Hash import SHA256

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
logger = logging.getLogger(__name__)

RAW_PUBLIC_KEY = os.environ.get("PUBLIC_KEY", "")
ENTITY_SECRET  = os.environ.get("ENTITY_SECRET", "")
API_KEY        = os.environ.get("API_KEY", "")

RATE_LIMIT = "30/minute"


def format_public_key(key: str) -> str:
    key = key.strip()
    if key.startswith("-----BEGIN"):
        return key.replace("\\n", "\n")
    for tag in ["-----BEGIN PUBLIC KEY-----", "-----END PUBLIC KEY-----",
                "-----BEGIN RSA PUBLIC KEY-----", "-----END RSA PUBLIC KEY-----"]:
        key = key.replace(tag, "")
    key = key.replace("\\n", "").replace("\n", "").replace(" ", "")
    lines = [key[i:i+64] for i in range(0, len(key), 64)]
    return "-----BEGIN PUBLIC KEY-----\n" + "\n".join(lines) + "\n-----END PUBLIC KEY-----"


PUBLIC_KEY = format_public_key(RAW_PUBLIC_KEY)


def real_client_ip(request: Request) -> str:
    """
    Extract real client IP respecting proxy headers.
    Priority: CF-Connecting-IP > X-Forwarded-For (first entry) > direct host.
    """
    cf = request.headers.get("CF-Connecting-IP", "").strip()
    if cf:
        return cf
    fwd = request.headers.get("X-Forwarded-For", "").strip()
    if fwd:
        return fwd.split(",")[0].strip()
    return request.client.host if request.client else "unknown"


limiter = Limiter(key_func=real_client_ip, default_limits=[])

app = FastAPI(docs_url=None, redoc_url=None, openapi_url=None)
app.state.limiter = limiter
app.add_middleware(SlowAPIMiddleware)


def _unauthorized() -> JSONResponse:
    return JSONResponse(status_code=401, content={"error": "unauthorized"})


@app.exception_handler(StarletteHTTPException)
async def http_exception_handler(request: Request, exc: StarletteHTTPException):
    if exc.status_code == 404:
        return HTMLResponse(content="", status_code=200)
    return JSONResponse(status_code=exc.status_code, content={"error": "unauthorized"})


@app.exception_handler(RequestValidationError)
async def validation_exception_handler(request: Request, exc: RequestValidationError):
    return JSONResponse(status_code=400, content={"error": "bad request"})


@app.exception_handler(RateLimitExceeded)
async def rate_limit_handler(request: Request, exc: RateLimitExceeded):
    ip = real_client_ip(request)
    logger.warning("ts=%s outcome=rate_limited ip=%s", datetime.utcnow().isoformat(), ip)
    return JSONResponse(status_code=429, content={"error": "too many requests"})


@app.get("/", response_class=HTMLResponse)
async def root():
    return HTMLResponse(content="", status_code=200)


@app.get("/health")
async def health():
    return {"status": "ok"}


@app.get("/generate")
@limiter.limit(RATE_LIMIT)
async def generate_ciphertext(request: Request):
    ts = datetime.utcnow().isoformat()

    # Block browser-origin requests
    user_agent = request.headers.get("user-agent", "").lower()
    accept     = request.headers.get("accept", "")
    origin     = request.headers.get("origin", "")

    is_browser = any(b in user_agent for b in ["mozilla", "chrome", "safari", "edge", "opera"])
    if is_browser or "text/html" in accept or origin:
        logger.warning("ts=%s outcome=blocked_browser", ts)
        return _unauthorized()

    # Auth check — generic response regardless of reason
    provided_key = request.headers.get("X-API-Key", "")
    if not API_KEY or not provided_key or provided_key != API_KEY:
        logger.warning("ts=%s outcome=unauthorized", ts)
        return _unauthorized()

    # Crypto
    try:
        entity_bytes = bytes.fromhex(ENTITY_SECRET)
    except (binascii.Error, ValueError):
        logger.error("ts=%s outcome=config_error", ts)
        return JSONResponse(status_code=500, content={"error": "internal error"})

    try:
        public_key     = RSA.import_key(PUBLIC_KEY)
        cipher         = PKCS1_OAEP.new(key=public_key, hashAlgo=SHA256)
        encrypted_data = cipher.encrypt(entity_bytes)
        encrypted_b64  = base64.b64encode(encrypted_data).decode()
    except Exception:
        logger.error("ts=%s outcome=crypto_error", ts)
        return JSONResponse(status_code=500, content={"error": "internal error"})

    logger.info("ts=%s outcome=success", ts)

    return JSONResponse(
        content={
            "idempotencyKey":        str(uuid4()),
            "entitySecretCiphertext": encrypted_b64,
        },
        headers={
            "Cache-Control":         "no-store",
            "X-Content-Type-Options": "nosniff",
        }
    )
