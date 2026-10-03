import json
from fastapi import Request
from fastapi.responses import JSONResponse
from starlette.concurrency import run_in_threadpool
from .configuration import mode, configuration
from .authentication import verify_request
from .service import Executor


def register_executor(app):
    @app.post("/internal/v1/operations/{operation_id}/execute")
    async def execute(operation_id: str, request: Request):
        try:
            if mode() != "executor":
                return JSONResponse(status_code=503, content={"error": "EXECUTOR_DISABLED"})
            body = bytearray()
            async for chunk in request.stream():
                body.extend(chunk)
                if len(body) > 1024:
                    return JSONResponse(status_code=413, content={"error": "REQUEST_TOO_LARGE"})
            config = configuration()
            verify_request(request.headers.get("authorization", "").removeprefix("Bearer "), "POST",
                           request.url.path, bytes(body), config.environment, config.public_keys)
            envelope = json.loads(body)
            if envelope != {"schemaVersion": 1} or type(envelope.get("schemaVersion")) is not int:
                return JSONResponse(status_code=400, content={"error": "INVALID_REQUEST"})
            result = await run_in_threadpool(Executor(config).execute, operation_id)
            return JSONResponse(status_code=202, content=result, headers={"Cache-Control": "no-store"})
        except Exception:
            return JSONResponse(status_code=403, content={"error": "EXECUTION_REQUEST_REJECTED"})
