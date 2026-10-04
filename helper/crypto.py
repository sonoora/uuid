import base64
import os
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Hash import SHA256
from .errors import HelperError


def encrypt_secret():
    try:
        secret = bytes.fromhex(os.environ.get("ENTITY_SECRET", ""))
        raw = os.environ.get("PUBLIC_KEY", "").replace("\\n", "\n").strip()
        if not raw.startswith("-----BEGIN"):
            raw = "-----BEGIN PUBLIC KEY-----\n" + raw + "\n-----END PUBLIC KEY-----"
        key = RSA.import_key(raw)
        if len(secret) != 32 or key.size_in_bits() < 2048:
            raise ValueError()
        return base64.b64encode(
            PKCS1_OAEP.new(key=key, hashAlgo=SHA256).encrypt(secret)
        ).decode("ascii")
    except (ValueError, TypeError, IndexError):
        raise HelperError("HELPER_UNAVAILABLE", 503) from None
