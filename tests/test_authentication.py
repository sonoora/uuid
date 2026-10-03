import base64
import hashlib
import time
import unittest
from uuid import uuid4
from Crypto.PublicKey import RSA
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256
from executor.authentication import encode, verify_request


class AuthenticationTests(unittest.TestCase):
    def test_pinned_api_identity_rejects_expiry_revocation_and_request_tampering(self):
        key = RSA.generate(2048)
        now = int(time.time())
        claims = dict(iss="sonoora-circle-execution", aud="uuid", sub="api-worker", scope="execution.request",
                      environment="local", iat=now, nbf=now, exp=now + 60, jti=str(uuid4()),
                      method="POST", path="/operation", bodyHash=hashlib.sha256(b"{}").hexdigest())
        public = {"fixture": key.public_key().export_key().decode()}
        def token(values, algorithm="RS256"):
            message = encode(dict(alg=algorithm, typ="JWT", kid="fixture")) + "." + encode(values)
            signature = pkcs1_15.new(key).sign(SHA256.new(message.encode()))
            return message + "." + base64.urlsafe_b64encode(signature).rstrip(b"=").decode()
        valid = token(claims)
        verify_request(valid, "POST", "/operation", b"{}", "local", public, now)
        for field, value in [("iss", "other"), ("aud", "api"), ("scope", "execution.report"), ("sub", "browser"),
                             ("environment", "production"), ("exp", now), ("nbf", now + 30), ("bodyHash", "wrong"),
                             ("path", "/other"), ("method", "GET"), ("jti", None)]:
            with self.subTest(field=field), self.assertRaises(ValueError):
                verify_request(token({**claims, field: value}), "POST", "/operation", b"{}", "local", public, now)
        for candidate, keys in [(token(claims, "none"), public), (valid, {})]:
            with self.assertRaises(ValueError):
                verify_request(candidate, "POST", "/operation", b"{}", "local", keys, now)


if __name__ == "__main__":
    unittest.main()
