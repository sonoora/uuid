import json
import os
from .errors import HelperError


def validate_policy(caller, context: dict, env=None):
    env = os.environ if env is None else env
    if env.get("UUID_ISSUANCE_ENABLED") != "true":
        raise HelperError("ISSUANCE_PAUSED", 503)
    if context["environment"] != caller.environment:
        raise HelperError("SCOPE_REJECTED", 403)
    try:
        policy = json.loads(env["UUID_POLICY_" + caller.environment.upper()])
        if set(policy) != {
            "accountRef",
            "blockchains",
            "walletSetIds",
            "tokenAddresses",
            "version",
        }:
            raise ValueError()
        if not all(
            isinstance(policy[k], list)
            and policy[k]
            and all(isinstance(v, str) and v for v in policy[k])
            for k in ("blockchains", "walletSetIds", "tokenAddresses")
        ):
            raise ValueError()
        if not all(
            isinstance(policy[k], str) and 0 < len(policy[k]) <= 160
            for k in ("accountRef", "version")
        ):
            raise ValueError()
    except (KeyError, ValueError, TypeError):
        raise HelperError("HELPER_UNAVAILABLE", 503) from None
    command = context["command"]
    if context["circleAccountRef"] != policy["accountRef"]:
        raise HelperError("SCOPE_REJECTED", 403)
    if command["type"] == "wallet.create":
        allowed = command["walletSetId"] in policy["walletSetIds"] and all(
            b in policy["blockchains"] for b in command["blockchains"]
        )
        allowed = allowed and context["purpose"] == "wallet_create"
    else:
        allowed = command["blockchain"] in policy["blockchains"] and command[
            "tokenAddress"
        ].lower() in [v.lower() for v in policy["tokenAddresses"]]
        allowed = allowed and (
            (command["type"] == "wallet.deploy")
            == (context["purpose"] == "wallet_deploy")
        )
        allowed = allowed and context["purpose"] != "wallet_create"
    if not allowed:
        raise HelperError("SCOPE_REJECTED", 403)
    return policy["version"]
