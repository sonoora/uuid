from fastapi import FastAPI, Request
import logging
import json
import os
from fastapi.responses import JSONResponse
from starlette.concurrency import run_in_threadpool
from .auth import authenticate
from .contracts import parse_envelope, request_identifier
from .errors import HelperError
from .journal import Journal
from .pass_wallets import material
from .service import Issuer


def create_app(issuer=None, journal=None, env=None):
    app = FastAPI(docs_url=None, redoc_url=None, openapi_url=None)
    journal = journal or Journal()
    issuer = issuer or Issuer(journal, env=env)

    @app.middleware("http")
    async def safe_errors(request, call_next):
        try:
            response = await call_next(request)
        except Exception as error:
            logging.getLogger(__name__).error("uuid.request.failed exception_type=%s", type(error).__name__)
            response = JSONResponse({"error": "HELPER_UNAVAILABLE"}, status_code=503)
        response.headers["Cache-Control"] = "no-store"
        response.headers["X-Content-Type-Options"] = "nosniff"
        return response

    @app.exception_handler(HelperError)
    async def helper_error(request, error):
        headers = {"Retry-After": "60"} if error.status == 429 else None
        return JSONResponse(
            {"error": error.code}, status_code=error.status, headers=headers
        )

    def caller(request):
        if len(request.headers.getlist("x-api-key")) != 1:
            raise HelperError("UNAUTHORIZED", 401)
        return authenticate(request.headers["x-api-key"], env)

    @app.get("/health")
    async def health():
        return {"status": "ok"}

    @app.get("/generate")
    async def retired():
        raise HelperError("CONTEXT_REQUIRED", 410)

    @app.post("/internal/v1/ciphertext")
    async def issue(request: Request):
        identity = caller(request)
        if (
            request.headers.get("content-type", "").split(";")[0].strip().lower()
            != "application/json"
        ):
            raise HelperError("INVALID_MEDIA_TYPE", 415)
        raw = bytearray()
        async for chunk in request.stream():
            raw.extend(chunk)
            if len(raw) > 16384:
                raise HelperError("REQUEST_TOO_LARGE", 413)
        envelope = parse_envelope(bytes(raw))
        return await run_in_threadpool(issuer.issue, identity, envelope)

    @app.post("/internal/v1/pass-wallets/material")
    async def pass_wallet_material(request: Request):
        if request.headers.get("content-type", "").partition(";")[0].strip().lower() != "application/json":
            raise HelperError("INVALID_MEDIA_TYPE", 415)
        body = bytearray()
        async for chunk in request.stream():
            if len(body) + len(chunk) > 512:
                raise HelperError("REQUEST_TOO_LARGE", 413)
            body.extend(chunk)
        try:
            payload = json.loads(body)
        except (ValueError, UnicodeError):
            raise HelperError("INVALID_REQUEST", 400) from None
        headers = request.headers.getlist("x-api-key")
        key = headers[0] if len(headers) == 1 else None
        return await run_in_threadpool(material, key, payload, os.environ if env is None else env)

    @app.get("/internal/v1/ciphertext/requests/{request_id}")
    async def receipt(request_id: str, request: Request):
        return await run_in_threadpool(
            journal.lookup, caller(request), request_identifier(request_id)
        )

    return app
