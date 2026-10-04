import hashlib
import rfc8785


def digest(domain: str, value) -> str:
    return hashlib.sha256(
        ("sonoora:" + domain + ":v1\n").encode() + rfc8785.dumps(value)
    ).hexdigest()
