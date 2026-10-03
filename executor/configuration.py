import json
import os
from dataclasses import dataclass
from urllib.parse import urlsplit


def required(name):
    value = os.environ.get(name, "").strip()
    if not value:
        raise ValueError("EXECUTOR_CONFIGURATION_MISSING")
    return value


def mode():
    value = os.environ.get("CIRCLE_EXECUTION_MODE", "legacy")
    if value not in ("legacy", "executor", "paused"):
        raise ValueError("EXECUTOR_MODE_INVALID")
    return value


@dataclass(frozen=True)
class Configuration:
    environment: str
    account: str
    authority: str
    private_key: str
    key_id: str
    public_keys: dict
    circle_key: str
    entity_secret: str
    circle_public_key: str
    token: str
    blockchain: str
    wallet_set: str
    deploy_destination: str


def configuration():
    authority = required("CIRCLE_EXECUTION_AUTHORITY_URL").rstrip("/")
    url = urlsplit(authority)
    if url.scheme != "https" or not url.hostname or url.username or url.password or url.path or url.query or url.fragment:
        raise ValueError("AUTHORITY_ORIGIN_INVALID")
    return Configuration(required("CIRCLE_EXECUTION_ENVIRONMENT"), required("CIRCLE_EXECUTION_ACCOUNT_REF"), authority,
                         required("CIRCLE_EXECUTION_SIGNING_KEY"), required("CIRCLE_EXECUTION_KEY_ID"),
                         json.loads(required("CIRCLE_API_PUBLIC_KEYS")), required("CIRCLE_API_KEY"), required("ENTITY_SECRET"),
                         required("PUBLIC_KEY"), required("CIRCLE_USDC_TOKEN_ADDRESS_MATIC"),
                         required("CIRCLE_EXECUTION_BLOCKCHAIN"), required("CIRCLE_WALLET_SET_ID"),
                         "0x1b360de493ba6e99d4a1e51d64e2de4b6b0cbdd2")
