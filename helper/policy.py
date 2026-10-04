import os
from .errors import HelperError


def validate_policy(caller, context: dict, env=None):
    env = os.environ if env is None else env
    if env.get("UUID_ISSUANCE_ENABLED") != "true":
        raise HelperError("ISSUANCE_PAUSED", 503)
    if context["environment"] != caller.environment:
        raise HelperError("SCOPE_REJECTED", 403)
