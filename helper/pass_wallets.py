"""Server-to-server security material for the three PASS wallets on Bubble Main/test."""

import hmac
import re
from uuid import UUID

from .crypto import encrypt_secret
from .errors import HelperError


PREVIEW_BRANCH = "feature/pass-wallets-preview"
OPERATIONS = ("create", "main", "escrow", "public")
PASS_ID = re.compile(r"[0-9]{13}x[0-9]{12,22}")
HEX_SECRET = re.compile(r"[0-9a-f]{64}")


def material(caller, payload, env, encrypt=encrypt_secret):
    if env.get("VERCEL_ENV") != "preview" or env.get("VERCEL_GIT_COMMIT_REF") != PREVIEW_BRANCH:
        raise HelperError("NOT_FOUND", 404)
    token = env.get("PASS_WALLETS_BUBBLE_TOKEN", "")
    seed = env.get("PASS_WALLETS_IDEMPOTENCY_SECRET", "")
    if not HEX_SECRET.fullmatch(token) or not HEX_SECRET.fullmatch(seed) or token == seed:
        raise HelperError("WALLETS_CONFIGURATION", 503)
    if not isinstance(caller, str) or not HEX_SECRET.fullmatch(caller) or not hmac.compare_digest(caller, token):
        raise HelperError("UNAUTHORIZED", 401)
    if not isinstance(payload, dict) or set(payload) != {"pass_id"}:
        raise HelperError("INVALID_REQUEST", 400)
    pass_id = payload["pass_id"]
    # Bubble's connector needs a typed example. This path never issues security material.
    if pass_id == "connector-schema":
        return {f"{op}_{field}": "schema-only" for op in OPERATIONS for field in ("key", "ciphertext")}
    if not isinstance(pass_id, str) or not PASS_ID.fullmatch(pass_id):
        raise HelperError("INVALID_PASS", 400)

    result = {}
    for op in OPERATIONS:
        # Same Pass + operation always produces the same pseudorandom UUID, including after a timeout.
        label = f"spaybubbleapps/test/pass-wallets/v1/{pass_id}/{op}".encode("ascii")
        digest = hmac.digest(bytes.fromhex(seed), label, "sha256")
        result[f"{op}_key"] = str(UUID(bytes=digest[:16], version=4))
        result[f"{op}_ciphertext"] = encrypt()
    return result
