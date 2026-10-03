import re
from uuid import UUID


def validate(command, config, operation_id):
    if (command.get("operationId") != operation_id or command.get("environment") != config.environment
        or command.get("account") != config.account or not command.get("ownerId")
        or not command.get("linkId") or not command.get("sourceId")):
        raise ValueError("COMMAND_IDENTITY_INVALID")
    key = UUID(command["providerIdempotencyKey"])
    if key.version != 4:
        raise ValueError("COMMAND_KEY_INVALID")
    payload = command["payload"]
    kind = command["operationType"]
    if kind == "wallet.create":
        if (set(payload) != {"accountType", "blockchains", "count", "metadata", "walletSetId"}
            or payload["accountType"] != "SCA" or payload["blockchains"] != [config.blockchain]
            or type(payload["count"]) is not int or payload["count"] != 1 or payload["walletSetId"] != config.wallet_set
            or not isinstance(payload["metadata"], list) or len(payload["metadata"]) != 1
            or set(payload["metadata"][0]) != {"name", "refId"}
            or not all(isinstance(v, str) and 0 < len(v) <= 100 for v in payload["metadata"][0].values())):
            raise ValueError("WALLET_COMMAND_INVALID")
        return "/v1/w3s/developer/wallets"
    if kind not in ("token.transfer", "wallet.deploy"):
        raise ValueError("OPERATION_NOT_ALLOWED")
    if (set(payload) != {"walletId", "destinationAddress", "amounts", "tokenAddress", "blockchain", "feeLevel", "refId"}
        or payload["blockchain"] != config.blockchain or payload["tokenAddress"].lower() != config.token.lower()
        or payload["feeLevel"] != "LOW" or not isinstance(payload["walletId"], str) or not payload["walletId"]
        or not isinstance(payload["refId"], str) or not 0 < len(payload["refId"]) <= 100
        or not re.fullmatch(r"0x[0-9a-fA-F]{40}", payload["destinationAddress"])
        or not isinstance(payload["amounts"], list) or len(payload["amounts"]) != 1
        or not isinstance(payload["amounts"][0], str) or not re.fullmatch(r"\d+(\.\d{1,6})?", payload["amounts"][0])):
        raise ValueError("TRANSFER_COMMAND_INVALID")
    if kind == "wallet.deploy":
        if payload["amounts"] != ["0"] or payload["destinationAddress"].lower() != config.deploy_destination.lower():
            raise ValueError("DEPLOY_COMMAND_INVALID")
    elif not re.search(r"[1-9]", payload["amounts"][0]):
        raise ValueError("TRANSFER_AMOUNT_INVALID")
    return "/v1/w3s/developer/transactions/transfer"
