import base64
import os
import logging
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Hash import SHA256
from .errors import HelperError


def format_public_key(raw: str) -> str:
    """Preserve the deployed helper's accepted PEM/base64 configuration formats."""
    raw = raw.strip()
    if raw.startswith("-----BEGIN"):
        return raw.replace("\\n", "\n")
    for tag in ("-----BEGIN PUBLIC KEY-----", "-----END PUBLIC KEY-----",
                "-----BEGIN RSA PUBLIC KEY-----", "-----END RSA PUBLIC KEY-----"):
        raw = raw.replace(tag, "")
    raw = raw.replace("\\n", "").replace("\n", "").replace(" ", "")
    lines = [raw[i:i + 64] for i in range(0, len(raw), 64)]
    return "-----BEGIN PUBLIC KEY-----\n" + "\n".join(lines) + "\n-----END PUBLIC KEY-----"


def encrypt_secret():
    stage = "secret_decode"
    try:
        secret = bytes.fromhex(os.environ.get("ENTITY_SECRET", ""))
        stage = "public_key_parse"
        raw = format_public_key(os.environ.get("PUBLIC_KEY", ""))
        key = RSA.import_key(raw)
        stage = "configuration_validation"
        if len(secret) != 32 or key.size_in_bits() < 2048:
            raise ValueError()
        stage = "encryption"
        return base64.b64encode(
            PKCS1_OAEP.new(key=key, hashAlgo=SHA256).encrypt(secret)
        ).decode("ascii")
    except (ValueError, TypeError, IndexError):
        logging.getLogger(__name__).error("uuid.crypto.failed stage=%s", stage)
        raise HelperError("HELPER_UNAVAILABLE", 503) from None
