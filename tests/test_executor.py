import copy
import json
import unittest
from dataclasses import replace
from uuid import uuid4
from unittest.mock import patch
from Crypto.PublicKey import RSA
from fastapi.testclient import TestClient
from executor.configuration import Configuration
from executor.service import Executor, ciphertext
from executor.command import validate
from executor.balance import verify_balance
from main import app


class ExecutorTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        key = RSA.generate(2048)
        cls.config = Configuration("local", "fixture", "https://authority.test", key.export_key().decode(),
                                   "fixture", {}, "synthetic-api-key", "11" * 32,
                                   key.public_key().export_key().decode(), "0x" + "2" * 40,
                                   "MATIC", "wallet-set", "0x" + "3" * 40)

    def setUp(self):
        self.command = dict(operationId=str(uuid4()), operationType="token.transfer", environment="local",
                            account="fixture", ownerId="owner", linkId="link", sourceId="source",
                            providerIdempotencyKey=str(uuid4()), payload=dict(walletId="wallet",
                            destinationAddress="0x" + "1" * 40, amounts=["1.000001"],
                            tokenAddress=self.config.token, blockchain="MATIC", feeLevel="LOW", refId="reference"))

    def test_crypto_uses_fresh_ciphertext_for_same_entity(self):
        self.assertNotEqual(ciphertext(self.config), ciphertext(self.config))
        with self.assertRaises(ValueError):
            ciphertext(replace(self.config, entity_secret="bad"))

    def test_command_allowlist_and_exact_economic_fields(self):
        validate(self.command, self.config, self.command["operationId"])
        changes = [("amounts", ["1e3"]), ("amounts", [1]), ("amounts", ["0"]),
                   ("amounts", ["1.0000001"]), ("blockchain", "ETH"), ("feeLevel", "HIGH"),
                   ("tokenAddress", "0x" + "9" * 40), ("url", "https://evil.test")]
        for key, value in changes:
            with self.subTest(key=key, value=value):
                command = copy.deepcopy(self.command)
                command["payload"][key] = value
                with self.assertRaises(ValueError):
                    validate(command, self.config, command["operationId"])
        with self.assertRaises(ValueError):
            validate(self.command, replace(self.config, account="different"), self.command["operationId"])

    def test_single_permit_no_resubmit_after_timeout_or_report_failure(self):
        for failure in (None, "provider", "report", "balance"):
            with self.subTest(failure=failure):
                permit = True
                writes, reports = [], []
                def transport(url, body, headers):
                    nonlocal permit
                    payload = json.loads(body)
                    if url.endswith("/claim"):
                        if not permit:
                            return 409, {}
                        permit = False
                        return 200, {"attemptId": "attempt", "command": self.command}
                    if url.endswith("/report"):
                        reports.append(payload)
                        return (503 if failure == "report" else 200), {}
                    writes.append(payload)
                    if failure == "provider":
                        raise TimeoutError("synthetic-secret-must-not-escape")
                    return 201, {"data": {"id": "transaction", "state": "INITIATED"}, "entitySecretCiphertext": "unsafe"}
                def balance(*args):
                    if failure == "balance":
                        raise ValueError("insufficient")
                executor = Executor(self.config, transport, balance)
                result = executor.execute(self.command["operationId"])
                executor.execute(self.command["operationId"])
                self.assertEqual(len(writes), 0 if failure == "balance" else 1)
                self.assertEqual(len(reports), 1)
                self.assertNotIn("synthetic-secret", json.dumps(result))
                self.assertNotIn("Ciphertext", json.dumps(reports))
                self.assertEqual(result["status"], "recorded" if failure is None else "outcome_unknown")

    def test_balance_requires_exact_chain_token_and_amount(self):
        def read(url, headers):
            return 200, {"data": {"tokenBalances": [{"amount": "1.000001", "token": {
                "tokenAddress": self.config.token, "blockchain": "MATIC"}}]}}
        verify_balance(self.command, self.config, read)
        command = copy.deepcopy(self.command)
        command["payload"]["amounts"] = ["1.000002"]
        with self.assertRaises(ValueError):
            verify_balance(command, self.config, read)
        with self.assertRaises(ValueError):
            verify_balance(self.command, replace(self.config, blockchain="ETH"), read)

    def test_legacy_endpoint_disabled_and_new_endpoint_requires_identity(self):
        client = TestClient(app)
        for mode in ("executor", "paused"):
            with patch.dict("os.environ", {"CIRCLE_EXECUTION_MODE": mode}):
                self.assertEqual(client.get("/generate").status_code, 410)
        with patch.dict("os.environ", {"CIRCLE_EXECUTION_MODE": "executor"}):
            self.assertEqual(client.post(f'/internal/v1/operations/{uuid4()}/execute', json={"schemaVersion": 1}).status_code, 403)
            self.assertEqual(client.post(f'/internal/v1/operations/{uuid4()}/execute', content="x" * 1025).status_code, 413)


if __name__ == "__main__":
    unittest.main()
