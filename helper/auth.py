import hmac
import os
import re
from dataclasses import dataclass
from .errors import HelperError


@dataclass(frozen=True)
class Caller:
    name: str
    environment: str


def authenticate(key: str, env=None) -> Caller:
    env = os.environ if env is None else env
    dev, prod = env.get("API_KEY_DEV", ""), env.get("API_KEY_PROD", "")
    if not all(
        re.fullmatch(r"[a-f0-9]{64}", v) for v in (dev, prod)
    ) or hmac.compare_digest(dev, prod):
        raise HelperError("HELPER_UNAVAILABLE", 503)
    candidate = key if re.fullmatch(r"[a-f0-9]{64}", key) else "0" * 64
    matches = (
        hmac.compare_digest(candidate, dev),
        hmac.compare_digest(candidate, prod),
    )
    if not re.fullmatch(r"[a-f0-9]{64}", key) or sum(matches) != 1:
        raise HelperError("UNAUTHORIZED", 401)
    return Caller("api-dev", "dev") if matches[0] else Caller("api-prod", "prod")
