"""Pinned RS256 service identities bound to an exact HTTP request."""
import base64
import hashlib
import json
import time
import uuid
from Crypto.Hash import SHA256
from Crypto.PublicKey import RSA
from Crypto.Signature import pkcs1_15


def encode(value):
    return base64.urlsafe_b64encode(json.dumps(value, separators=(",", ":")).encode()).rstrip(b"=").decode()


def decode(value):
    return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))


def sign_request(method, path, body, environment, private_key, key_id, scope):
    now = int(time.time())
    claims = dict(iss="sonoora-circle-execution", aud="api", sub="uuid", scope=scope,
                  environment=environment, iat=now, nbf=now, exp=now + 60, jti=str(uuid.uuid4()),
                  method=method, path=path, bodyHash=hashlib.sha256(body).hexdigest())
    message = f'{encode(dict(alg="RS256", typ="JWT", kid=key_id))}.{encode(claims)}'
    key = RSA.import_key(private_key.replace("\\n", "\n"))
    if key.size_in_bits() < 2048:
        raise ValueError("SERVICE_KEY_INVALID")
    signature = pkcs1_15.new(key).sign(SHA256.new(message.encode()))
    return message + "." + base64.urlsafe_b64encode(signature).rstrip(b"=").decode()


def verify_request(token, method, path, body, environment, public_keys, now=None):
    try:
        if len(token) > 8192:
            raise ValueError()
        header, claims, signature = token.split(".")
        h, c = json.loads(decode(header)), json.loads(decode(claims))
        if h.get("alg") != "RS256" or h.get("typ") != "JWT":
            raise ValueError()
        key = RSA.import_key(public_keys[h["kid"]].replace("\\n", "\n"))
        if key.size_in_bits() < 2048:
            raise ValueError()
        pkcs1_15.new(key).verify(
            SHA256.new(f"{header}.{claims}".encode()), decode(signature))
        current = int(time.time()) if now is None else now
        if (c.get("iss") != "sonoora-circle-execution" or c.get("aud") != "uuid"
            or c.get("sub") != "api-worker" or c.get("scope") != "execution.request"
            or c.get("environment") != environment or type(c.get("iat")) is not int
            or type(c.get("nbf")) is not int or c["nbf"] != c["iat"] or c["nbf"] > current + 15
            or type(c.get("exp")) is not int or c["exp"] <= current or c["iat"] > current + 15
            or not 0 < c["exp"] - c["iat"] <= 60 or not c.get("jti")
            or c.get("method") != method or c.get("path") != path
            or c.get("bodyHash") != hashlib.sha256(body).hexdigest()):
            raise ValueError()
        return c
    except (ValueError, KeyError, TypeError, AttributeError, UnicodeError):
        raise ValueError("SERVICE_UNAUTHORIZED") from None
