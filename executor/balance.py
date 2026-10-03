"""Read balance only after acquiring the API's durable, exclusive source reservation."""
from decimal import Decimal, InvalidOperation
from urllib.parse import quote, urlencode
from .transport import get_json


def verify_balance(command, config, read=get_json):
    if command["operationType"] != "token.transfer":
        return
    payload = command["payload"]
    url = ("https://api.circle.com/v1/w3s/wallets/" + quote(payload["walletId"], safe="")
           + "/balances?" + urlencode({"tokenAddress": config.token, "pageSize": 50}))
    status, response = read(url, {"Authorization": f"Bearer {config.circle_key}"})
    rows = response.get("data", {}).get("tokenBalances", [])
    matches = [row for row in rows if isinstance(row, dict)
               and row.get("token", {}).get("tokenAddress", "").lower() == config.token.lower()
               and row.get("token", {}).get("blockchain") == config.blockchain]
    if status != 200 or len(matches) != 1:
        raise ValueError("SOURCE_BALANCE_UNVERIFIED")
    try:
        available = Decimal(matches[0]["amount"])
        required = Decimal(payload["amounts"][0])
        if not available.is_finite() or available < required:
            raise ValueError("SOURCE_BALANCE_INSUFFICIENT")
    except (InvalidOperation, KeyError, TypeError):
        raise ValueError("SOURCE_BALANCE_UNVERIFIED") from None
