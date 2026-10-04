import base64
import hashlib
from datetime import datetime, timezone
from uuid import uuid4
from .canonical import digest
from .crypto import encrypt_secret
from .policy import validate_policy


class Issuer:
    def __init__(self, journal, encrypt=encrypt_secret, env=None):
        self.journal, self.encrypt, self.env = journal, encrypt, env

    def issue(self, caller, envelope):
        context = envelope["context"]
        validate_policy(caller, context, self.env)
        key = self.journal.prepare(caller, envelope)
        # Never cache or return a previously issued ciphertext, including after a lost response.
        ciphertext = self.encrypt()
        receipt = {
            "schemaVersion": "uuid-audit-receipt-v1",
            "issuanceId": str(uuid4()),
            "requestId": envelope["requestId"],
            "idempotencyKey": key,
            "verifiedCaller": caller.name,
            "environment": caller.environment,
            "issuedAt": datetime.now(timezone.utc)
            .isoformat(timespec="milliseconds")
            .replace("+00:00", "Z"),
            "contextHash": digest("context", context),
            "requestHash": digest("request", envelope),
            "ciphertextHash": hashlib.sha256(
                base64.b64decode(ciphertext, validate=True)
            ).hexdigest(),
        }
        receipt["issuanceHash"] = digest("issuance", receipt)
        self.journal.record(
            caller, receipt
        )  # Commit must succeed before releasing material.
        return {
            "idempotencyKey": key,
            "entitySecretCiphertext": ciphertext,
            "audit": receipt,
        }
