import base64
import json
import re
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Hash import SHA256
from .authentication import sign_request
from .command import validate
from .transport import post_json
from .balance import verify_balance


def encode(value):
    return json.dumps(value, separators=(",", ":")).encode()


def ciphertext(config):
    key = config.circle_public_key.replace("\\n", "\n")
    if not key.startswith("-----BEGIN"):
        key = "-----BEGIN PUBLIC KEY-----\n" + key + "\n-----END PUBLIC KEY-----"
    secret = bytes.fromhex(config.entity_secret)
    if len(secret) != 32:
        raise ValueError("ENTITY_CONFIGURATION_INVALID")
    return base64.b64encode(PKCS1_OAEP.new(RSA.import_key(key), hashAlgo=SHA256).encrypt(secret)).decode()


def safe_result(value):
    """Only provider response fields needed for recovery/projection cross the boundary."""
    allowed = {"data", "wallets", "wallet", "transaction", "id", "transactionId", "state", "transactionState",
               "address", "accountType", "blockchain", "blockchains", "custodyType", "name", "refId", "scaCore",
               "walletSetId", "createDate", "code"}
    if isinstance(value, dict):
        return {k: safe_result(v) for k, v in value.items() if k in allowed}
    if isinstance(value, list):
        return [safe_result(v) for v in value[:200]]
    if value is None or isinstance(value, (str, int, float, bool)):
        return value
    return None


class Executor:
    def __init__(self, config, transport=post_json, balance_check=verify_balance):
        self.config, self.transport, self.balance_check = config, transport, balance_check

    def authority(self, operation_id, action, payload):
        path = f"/internal/v1/circle-operations/{operation_id}/{action}"
        body = encode(payload)
        token = sign_request("POST", path, body, self.config.environment, self.config.private_key,
                             self.config.key_id, f"execution.{action}")
        return self.transport(self.config.authority + path, body, {"Authorization": f"Bearer {token}"})

    def execute(self, operation_id):
        if not re.fullmatch(r"[a-f0-9-]{36}", operation_id):
            raise ValueError("OPERATION_ID_INVALID")
        status, claim = self.authority(operation_id, "claim", {"schemaVersion": 1})
        if status != 200:
            return {"status": "not_dispatched"}
        attempt = claim["attemptId"]
        result = None
        try:
            command = claim["command"]
            path = validate(command, self.config, operation_id)
            self.balance_check(command, self.config)
            body = {**command["payload"], "idempotencyKey": command["providerIdempotencyKey"],
                    "entitySecretCiphertext": ciphertext(self.config)}
            status, payload = self.transport("https://api.circle.com" + path, encode(body),
                                             {"Authorization": f"Bearer {self.config.circle_key}", "X-Request-Id": attempt})
            # HTTP failures stay uncertain; no broad classification turns an error into another payment.
            if 200 <= status < 300:
                result = {"statusCode": status, "payload": safe_result(payload), "rawBody": None}
        except Exception:
            # Never expose crypto, credentials, raw bodies or transport exception text.
            result = None
        reported, _ = self.authority(operation_id, "report", {"attemptId": attempt, "result": result})
        if reported != 200:
            return {"status": "outcome_unknown"}
        return {"status": "recorded" if result else "outcome_unknown"}
