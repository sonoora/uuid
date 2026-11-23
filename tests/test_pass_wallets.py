import base64
import unittest
from unittest.mock import patch
from uuid import UUID

from Crypto.Cipher import PKCS1_OAEP
from Crypto.Hash import SHA256
from Crypto.PublicKey import RSA
from fastapi.testclient import TestClient

from helper.pass_wallets import OPERATIONS, PREVIEW_BRANCH
from helper.routes import create_app


class PassWalletMaterialTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.key = RSA.generate(2048)

    def setUp(self):
        self.env = {
            "VERCEL_ENV": "preview", "VERCEL_GIT_COMMIT_REF": PREVIEW_BRANCH,
            "PASS_WALLETS_BUBBLE_TOKEN": "a" * 64, "PASS_WALLETS_IDEMPOTENCY_SECRET": "b" * 64,
        }
        self.path = "/internal/v1/pass-wallets/material"
        self.client = TestClient(create_app(env=self.env))
        self.payload = {"pass_id": "1794257700953x4599751051722096"}
        self.headers = {"X-API-Key": self.env["PASS_WALLETS_BUBBLE_TOKEN"]}
        crypto = patch.dict("os.environ", {
            "ENTITY_SECRET": "12" * 32, "PUBLIC_KEY": self.key.publickey().export_key().decode()
        })
        crypto.start()
        self.addCleanup(crypto.stop)

    def test_retry_keeps_four_keys_and_refreshes_every_ciphertext(self):
        first = self.client.post(self.path, json=self.payload, headers=self.headers)
        self.assertEqual(first.status_code, 200)
        self.assertEqual(first.headers["cache-control"], "no-store")
        second = self.client.post(self.path, json=self.payload, headers=self.headers).json()
        other = self.client.post(self.path, json={"pass_id": self.payload["pass_id"] + "0"}, headers=self.headers).json()
        keys, ciphertexts = set(), set()
        for role in OPERATIONS:
            key = first.json()[role + "_key"]
            self.assertEqual(UUID(key).version, 4)
            self.assertEqual(second[role + "_key"], key)
            self.assertNotEqual(other[role + "_key"], key)
            keys.add(key)
            for result in (first.json(), second):
                encrypted = result[role + "_ciphertext"]
                plain = PKCS1_OAEP.new(self.key, hashAlgo=SHA256).decrypt(base64.b64decode(encrypted))
                self.assertEqual(plain, bytes.fromhex("12" * 32))
                ciphertexts.add(encrypted)
        self.assertEqual(len(keys), 4)
        self.assertEqual(len(ciphertexts), 8)

    def test_schema_never_issues_material(self):
        with patch.dict("os.environ", {"ENTITY_SECRET": ""}):
            result = self.client.post(self.path, json={"pass_id": "connector-schema"}, headers=self.headers)
        self.assertEqual(result.status_code, 200)
        self.assertEqual(set(result.json().values()), {"schema-only"})

    def test_auth_scope_and_contract(self):
        self.assertEqual(self.client.post(self.path, json=self.payload).status_code, 401)
        for payload in ({"pass_id": ""}, {"pass_id": 42}, {**self.payload, "amount": 10}):
            self.assertEqual(self.client.post(self.path, json=payload, headers=self.headers).status_code, 400)
        for name, value in (("VERCEL_ENV", "production"), ("VERCEL_GIT_COMMIT_REF", "main"),
                            ("PASS_WALLETS_IDEMPOTENCY_SECRET", "")):
            with patch.dict(self.env, {name: value}):
                status = self.client.post(self.path, json=self.payload, headers=self.headers).status_code
                self.assertEqual(status, 503 if name.endswith("SECRET") else 404)
