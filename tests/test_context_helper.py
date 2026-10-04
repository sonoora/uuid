import copy
import json
import threading
import unittest
from datetime import datetime, timezone
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
from helper.service import Issuer

DEV, PROD = "a" * 64, "b" * 64
WALLET = "11111111-1111-4111-8111-111111111111"
TOKEN = "0x" + "1" * 40
POLICY = {
    "accountRef": "fixture-account",
    "blockchains": ["MATIC"],
    "walletSetIds": [WALLET],
    "tokenAddresses": [TOKEN],
    "version": "fixture-v1",
}
ENV = {
    "API_KEY_DEV": DEV,
    "API_KEY_PROD": PROD,
    "UUID_ISSUANCE_ENABLED": "true",
    "UUID_POLICY_DEV": json.dumps(POLICY),
    "UUID_POLICY_PROD": json.dumps(POLICY),
}


def envelope():
    return {
        "schemaVersion": "uuid-context-v1",
        "requestId": str(uuid4()),
        "attemptId": str(uuid4()),
        "requestedAt": datetime.now(timezone.utc)
        .isoformat(timespec="milliseconds")
        .replace("+00:00", "Z"),
        "context": {
            "operationId": str(uuid4()),
            "providerIdempotencyKey": str(uuid4()),
            "environment": "dev",
            "circleAccountRef": "fixture-account",
            "purpose": "cashback",
            "actor": {"type": "automation", "reference": "fixture"},
            "business": {},
            "command": {
                "type": "token.transfer",
                "walletId": WALLET,
                "blockchain": "MATIC",
                "tokenAddress": TOKEN,
                "destinationAddress": "0x" + "2" * 40,
                "amounts": ["1.25"],
                "feeLevel": "LOW",
                "refId": "fixture",
            },
        },
    }


class MemoryJournal:
    def __init__(self):
        self.rows = {}
        self.operations = {}
        self.fail = False
        self.lock = threading.Lock()

    def record(self, caller, context, receipt):
        with self.lock:
            if self.fail:
                raise HelperError("JOURNAL_UNAVAILABLE", 503)
            key = (caller.name, receipt["requestId"])
            operation = (caller.name, context["operationId"])
            if key in self.rows or (
                operation in self.operations and self.operations[operation] != context
            ):
                raise HelperError("CONTEXT_CONFLICT", 409)
            self.operations[operation] = copy.deepcopy(context)
            self.rows[key] = copy.deepcopy(receipt)

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

    def post(self, data, key=DEV):
        return self.client.post(
            "/internal/v1/ciphertext", json=data, headers={"X-API-Key": key}
        )

    def test_valid_crypto_and_receipt(self):
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
        self.assertEqual(p["idempotencyKey"], body["context"]["providerIdempotencyKey"])
        self.assertEqual(p["audit"]["contextHash"], digest("context", body["context"]))
        self.assertNotIn(
            "entitySecretCiphertext", json.dumps(list(self.store.rows.values()))
        )
        self.assertEqual(r.headers["cache-control"], "no-store")

    def test_two_emissions_fresh_cipher_same_operation(self):
        body = envelope()
        a = self.post(body).json()
        body["requestId"] = str(uuid4())
        b = self.post(body).json()
        self.assertNotEqual(a["entitySecretCiphertext"], b["entitySecretCiphertext"])
        self.assertEqual(a["idempotencyKey"], b["idempotencyKey"])

    def test_replay_no_material(self):
        body = envelope()
        self.assertEqual(self.post(body).status_code, 200)
        r = self.post(body)
        self.assertEqual(r.status_code, 409)
        self.assertNotIn("entitySecretCiphertext", r.text)

    def test_changed_context_rejected(self):
        body = envelope()
        self.post(body)
        body["requestId"] = str(uuid4())
        body["context"]["command"]["amounts"] = ["2"]
        self.assertEqual(self.post(body).status_code, 409)

    def test_database_failure_does_not_release(self):
        self.store.fail = True
        r = self.post(envelope())
        self.assertEqual(r.status_code, 503)
        self.assertNotIn("entitySecretCiphertext", r.text)

    def test_invalid_and_missing_auth(self):
        self.assertEqual(self.post(envelope(), "wrong").status_code, 401)
        self.assertEqual(
            self.client.post("/internal/v1/ciphertext", json=envelope()).status_code,
            401,
        )

    def test_duplicate_header_rejected(self):
        r = self.client.post(
            "/internal/v1/ciphertext",
            json=envelope(),
            headers=[("X-API-Key", DEV), ("X-API-Key", PROD)],
        )
        self.assertEqual(r.status_code, 401)

    def test_equal_or_missing_keys_fail_closed(self):
        for prod in (DEV, ""):
            with self.subTest(prod=bool(prod)):
                with self.assertRaises(HelperError):
                    authenticate(DEV, {"API_KEY_DEV": DEV, "API_KEY_PROD": prod})

    def test_cross_environment_and_lookup(self):
        body = envelope()
        self.assertEqual(self.post(body, PROD).status_code, 403)
        self.post(body)
        r = self.client.get(
            "/internal/v1/ciphertext/requests/" + body["requestId"],
            headers={"X-API-Key": PROD},
        )
        self.assertEqual(r.status_code, 404)
        r = self.client.get(
            "/internal/v1/ciphertext/requests/" + body["requestId"],
            headers={"X-API-Key": DEV},
        )
        self.assertEqual(r.status_code, 200)
        self.assertNotIn("entitySecretCiphertext", r.text)

    def test_forged_origin_does_not_authenticate(self):
        r = self.client.post(
            "/internal/v1/ciphertext",
            json=envelope(),
            headers={
                "Origin": "https://dev-api.sonoora.com",
                "X-Forwarded-For": "127.0.0.1",
            },
        )
        self.assertEqual(r.status_code, 401)

    def test_unknown_fields_and_amounts(self):
        for amount in ("0", "-1", "1e2", 1.2, "0.1234567"):
            b = envelope()
            b["context"]["command"]["amounts"] = [amount]
            self.assertEqual(self.post(b).status_code, 400)
        b = envelope()
        b["context"]["command"]["url"] = "https://example.com"
        self.assertEqual(self.post(b).status_code, 400)

    def test_stale_timestamp(self):
        b = envelope()
        b["requestedAt"] = "2020-01-01T00:00:00.000Z"
        self.assertEqual(self.post(b).status_code, 400)

    def test_duplicate_json_and_oversize(self):
        r = self.client.post(
            "/internal/v1/ciphertext",
            content='{"requestId":"a","requestId":"b"}',
            headers={"X-API-Key": DEV, "Content-Type": "application/json"},
        )
        self.assertEqual(r.status_code, 400)
        r = self.client.post(
            "/internal/v1/ciphertext",
            content="x" * 16385,
            headers={"X-API-Key": DEV, "Content-Type": "application/json"},
        )
        self.assertEqual(r.status_code, 413)

    def test_scope_and_pause(self):
        b = envelope()
        b["context"]["circleAccountRef"] = "other"
        self.assertEqual(self.post(b).status_code, 403)
        self.env["UUID_ISSUANCE_ENABLED"] = "false"
        self.assertEqual(self.post(envelope()).status_code, 503)

    def test_old_route_retired_and_unknown_not_success(self):
        self.assertEqual(
            self.client.get("/generate", headers={"X-API-Key": DEV}).status_code, 410
        )
        self.assertEqual(self.client.get("/unknown").status_code, 404)
        self.assertEqual(self.client.get("/internal/v1/ciphertext").status_code, 405)

    def test_canonical_unicode_and_key_order(self):
        self.assertEqual(
            digest("context", {"z": "á", "😀": 1, "a": [1, True]}),
            digest("context", {"a": [1, True], "😀": 1, "z": "á"}),
        )


if __name__ == "__main__":
    unittest.main()


class CrossLanguageVector(unittest.TestCase):
    def test_rfc8785_typescript_vector(self):
        self.assertEqual(
            digest(
                "context",
                {
                    "z": "a\u00e7\u00e3o\U0001f3b5",
                    "a": {"amount": "1.250000", "count": 1},
                },
            ),
            "b9217d7c739e5e06394ea2c30c0465dfe1fdde584d241128e5341bc2b5185617",
        )
