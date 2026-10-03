"""Local integration fixture. No external connections; all keys and provider effects are synthetic."""
import json
import sys
from pathlib import Path
from urllib.request import Request, urlopen
from urllib.error import HTTPError
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from executor.configuration import Configuration
from executor.authentication import verify_request
from executor.service import Executor

fixture = json.load(sys.stdin)
verify_request(fixture["token"], "POST", fixture["path"], fixture["body"].encode(), "local", {"fixture": fixture["publicKey"]})
config = Configuration("local", "fixture", "https://authority.test", fixture["privateKey"], "fixture", {},
                       "synthetic-provider-key", "11" * 32, fixture["publicKey"], "0x" + "2" * 40,
                       "MATIC", "set", "0x" + "3" * 40)
writes = 0


def transport(url, body, headers):
    global writes
    if url.startswith("https://authority.test/"):
        target = fixture["authority"] + url.removeprefix("https://authority.test")
        request = Request(target, data=body, headers={"Content-Type": "application/json", **headers}, method="POST")
        try:
            response = urlopen(request, timeout=5)
        except HTTPError as error:
            response = error
        with response:
            return response.status, json.load(response)
    if not url.startswith("https://api.circle.com/v1/w3s/developer/"):
        raise ValueError("EXTERNAL_NETWORK_FORBIDDEN")
    writes += 1
    if fixture.get("lostResponse"):
        raise TimeoutError("synthetic response loss")
    return 201, {"data": {"wallets": [{"id": "synthetic-wallet", "state": "LIVE"}]}}


result = Executor(config, transport, lambda *_: None).execute(fixture["operationId"])
print(json.dumps({"result": result, "writes": writes}))
