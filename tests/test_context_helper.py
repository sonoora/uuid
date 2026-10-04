import copy
import json
import threading
import unittest
from datetime import datetime, timezone, timedelta
from uuid import uuid4
from unittest.mock import patch
from fastapi.testclient import TestClient
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Hash import SHA256
import base64
from helper.auth import authenticate
from helper.canonical import digest
from helper.errors import HelperError
from helper.routes import create_app

DEV, PROD = "a" * 64, "b" * 64
ENV = {"API_KEY_DEV": DEV, "API_KEY_PROD": PROD, "UUID_ISSUANCE_ENABLED": "true"}


def envelope():
    return {
        "schemaVersion": "uuid-audit-v1",
        "requestId": str(uuid4()),
        "requestedAt": datetime.now(timezone.utc)
        .isoformat(timespec="milliseconds")
        .replace("+00:00", "Z"),
        "idempotencyKey": None,
        "context": {
            "environment": "dev",
            "purpose": "money_transfer",
            "actor": {"type": "automation", "reference": "fixture"},
            "details": {"amountDecimal": "1.25", "destinationAddress": "0x" + "2" * 40},
        },
    }


class MemoryJournal:
    def __init__(self):
        self.requests, self.rows = {}, {}
        self.fail_prepare = self.fail_record = False
        self.lock = threading.Lock()

    def prepare(self, caller, request):
        with self.lock:
            if self.fail_prepare:
                raise HelperError("JOURNAL_UNAVAILABLE", 503)
            key = (caller.name, request["requestId"])
            if key not in self.requests:
                self.requests[key] = (
                    copy.deepcopy(request),
                    request["idempotencyKey"] or str(uuid4()),
                )
            if self.requests[key][0] != request:
                raise HelperError("CONTEXT_CONFLICT", 409)
            return self.requests[key][1]

    def record(self, caller, receipt):
        if self.fail_record:
            raise HelperError("JOURNAL_UNAVAILABLE", 503)
        self.rows[(caller.name, receipt["requestId"])] = copy.deepcopy(receipt)

    def lookup(self, caller, request):
        if (caller.name, request) not in self.rows:
            raise HelperError("NOT_FOUND", 404)
        return self.rows[(caller.name, request)]


class HelperTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.key = RSA.generate(2048)

    def setUp(self):
        self.patch = patch.dict(
            "os.environ",
            {
                "ENTITY_SECRET": "1a" * 32,
                "PUBLIC_KEY": self.key.public_key().export_key().decode(),
            },
        )
        self.patch.start()
        self.addCleanup(self.patch.stop)
        self.store = MemoryJournal()
        self.env = dict(ENV)
        self.client = TestClient(create_app(journal=self.store, env=self.env))
        self.addCleanup(self.client.close)

    def post(self, body, key=DEV):
        return self.client.post(
            "/internal/v1/ciphertext", json=body, headers={"X-API-Key": key}
        )

    def test_crypto_receipt_and_no_secret_journal(self):
        body = envelope()
        r = self.post(body)
        self.assertEqual(r.status_code, 200)
        p = r.json()
        self.assertEqual(
            PKCS1_OAEP.new(self.key, hashAlgo=SHA256).decrypt(
                base64.b64decode(p["entitySecretCiphertext"])
            ),
            bytes.fromhex("1a" * 32),
        )
        self.assertEqual(p["audit"]["requestHash"], digest("request", body))
        rec = dict(p["audit"])
        h = rec.pop("issuanceHash")
        self.assertEqual(h, digest("issuance", rec))
        self.assertNotIn(p["entitySecretCiphertext"], str(self.store.rows))
        self.assertEqual(r.headers["cache-control"], "no-store")

    def test_retry_same_request_keeps_key_fresh_cipher(self):
        body = envelope()
        a = self.post(body).json()
        b = self.post(body).json()
        self.assertEqual(a["idempotencyKey"], b["idempotencyKey"])
        self.assertNotEqual(a["entitySecretCiphertext"], b["entitySecretCiphertext"])
        self.assertNotEqual(a["audit"]["issuanceId"], b["audit"]["issuanceId"])

    def test_existing_key_and_new_requests(self):
        body = envelope()
        body["idempotencyKey"] = str(uuid4())
        for _ in range(2):
            body["requestId"] = str(uuid4())
            self.assertEqual(
                self.post(body).json()["idempotencyKey"], body["idempotencyKey"]
            )

    def test_changed_context_same_request_rejected(self):
        body = envelope()
        self.post(body)
        body["context"]["details"]["amountDecimal"] = "2.00"
        self.assertEqual(self.post(body).status_code, 409)

    def test_journal_failures_no_material(self):
        for field in ["fail_prepare", "fail_record"]:
            setattr(self.store, field, True)
            r = self.post(envelope())
            self.assertEqual(r.status_code, 503)
            self.assertNotIn("Ciphertext", r.text)
            setattr(self.store, field, False)

    def test_prod_identity_and_spoofed_headers(self):
        body = envelope()
        body["context"]["environment"] = "prod"
        result = self.post(body, PROD)
        self.assertEqual(result.status_code, 200)
        self.assertEqual(result.json()["audit"]["verifiedCaller"], "api-prod")
        response = self.client.post(
            "/internal/v1/ciphertext",
            json=body,
            headers={
                "X-API-Key": DEV,
                "Origin": "https://api.sonoora.com",
                "X-Forwarded-For": "127.0.0.1",
            },
        )
        self.assertEqual(response.status_code, 403)
        self.assertEqual(
            self.client.post("/internal/v1/ciphertext", json=envelope()).status_code,
            401,
        )

    def test_wrong_environment(self):
        self.assertEqual(self.post(envelope(), PROD).status_code, 403)

    def test_wrong_key_and_same_config_keys(self):
        self.assertEqual(self.post(envelope(), "invalid").status_code, 401)
        self.env["API_KEY_PROD"] = DEV
        self.assertEqual(self.post(envelope()).status_code, 503)

    def test_pause(self):
        self.env["UUID_ISSUANCE_ENABLED"] = "false"
        self.assertEqual(self.post(envelope()).status_code, 503)

    def test_timestamp(self):
        for seconds in [-121, 31]:
            body = envelope()
            body["requestedAt"] = (
                (datetime.now(timezone.utc) + timedelta(seconds=seconds))
                .isoformat(timespec="milliseconds")
                .replace("+00:00", "Z")
            )
            self.assertEqual(self.post(body).status_code, 400)

    def test_unknown_float_null_fields(self):
        for details in [
            {"secret": "bad"},
            {"amountDecimal": 1.25},
            {"reference": None},
            {"route": "a\nb"},
        ]:
            body = envelope()
            body["context"]["details"] = details
            self.assertEqual(self.post(body).status_code, 400)

    def test_duplicate_keys_and_oversize(self):
        for raw, code in [
            ('{"schemaVersion":"x","schemaVersion":"y"}', 400),
            ("x" * 16385, 413),
        ]:
            r = self.client.post(
                "/internal/v1/ciphertext",
                content=raw,
                headers={"X-API-Key": DEV, "Content-Type": "application/json"},
            )
            self.assertEqual(r.status_code, code)

    def test_lookup_is_environment_scoped_without_material(self):
        body = envelope()
        self.post(body)
        path = "/internal/v1/ciphertext/requests/" + body["requestId"]
        r = self.client.get(path, headers={"X-API-Key": DEV})
        self.assertEqual(r.status_code, 200)
        self.assertNotIn("entitySecretCiphertext", r.text)
        self.assertEqual(
            self.client.get(path, headers={"X-API-Key": PROD}).status_code, 404
        )

    def test_cross_language_hash_fixture(self):
        context = {
            "environment": "dev",
            "purpose": "wallet_create",
            "actor": {"type": "automation", "reference": "fixture-ação"},
            "details": {"walletName": "mãe"},
        }
        self.assertEqual(
            digest("context", context),
            "038a0156a763d8a29c12ffcc18ac027de6f3deb87c92583b05f173c0d5274efe",
        )

    def test_legacy_and_no_docs(self):
        self.assertEqual(self.client.get("/generate").status_code, 410)
        self.assertEqual(self.client.get("/docs").status_code, 404)


if __name__ == "__main__":
    unittest.main()
