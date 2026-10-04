import json
from datetime import datetime, timezone
from typing import Annotated, Literal
from uuid import UUID
from pydantic import (
    BaseModel,
    ConfigDict,
    AfterValidator,
    StringConstraints,
    field_validator,
)
from .errors import HelperError


def validate_text_length(value: str) -> str:
    # Match JavaScript string length (UTF-16 units), including supplementary characters.
    if len(value.encode("utf-16-le")) > 320:
        raise ValueError("text length")
    return value


Text = Annotated[
    str,
    StringConstraints(min_length=1, max_length=160, pattern=r"^[^\x00-\x1f]+$"),
    AfterValidator(validate_text_length),
]
ProviderIdentifier = Annotated[
    str,
    StringConstraints(
        pattern=r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$"
    ),
]
Address = Annotated[str, StringConstraints(pattern=r"^0x[0-9a-fA-F]{40}$")]
Amount = Annotated[
    str, StringConstraints(pattern=r"^(0|[1-9][0-9]{0,29})(\.[0-9]{1,6})?$")
]


class Strict(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)


class Actor(Strict):
    type: Literal["user", "automation"]
    reference: Text


class Details(Strict):
    route: Text | None = None
    userId: Text | None = None
    profileId: Text | None = None
    linkId: Text | None = None
    transferIntentId: Text | None = None
    circleWalletId: Text | None = None
    reference: Text | None = None
    walletSetId: Text | None = None
    walletName: Text | None = None
    amountDecimal: Amount | None = None
    destinationAddress: Address | None = None
    blockchain: Text | None = None
    tokenAddress: Address | None = None


class Context(Strict):
    environment: Literal["dev", "prod"]
    purpose: Literal["wallet_create", "wallet_deploy", "money_transfer", "remediation"]
    actor: Actor
    details: Details


class Envelope(Strict):
    schemaVersion: Literal["uuid-audit-v1"]
    requestId: ProviderIdentifier
    requestedAt: str
    idempotencyKey: ProviderIdentifier | None
    context: Context

    @field_validator("requestedAt")
    @classmethod
    def timestamp(cls, value):
        datetime.strptime(value, "%Y-%m-%dT%H:%M:%S.%fZ")
        if len(value) != 24:
            raise ValueError("timestamp")
        return value


def parse_envelope(raw: bytes, now: datetime | None = None) -> dict:
    def unique(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise ValueError("duplicate")
            result[key] = value
        return result

    try:
        obj = json.loads(
            raw.decode("utf-8"),
            object_pairs_hook=unique,
            parse_constant=lambda _: (_ for _ in ()).throw(ValueError("nonfinite")),
        )
        parsed = Envelope.model_validate(obj)
        result = parsed.model_dump(exclude_none=True)
        result["idempotencyKey"] = parsed.idempotencyKey
        if result != obj:
            raise ValueError("noncanonical optional fields")
        # Reject noncanonical IDs, illegal Unicode and implicit numeric coercion.
        json.dumps(result, ensure_ascii=False).encode("utf-8")
        timestamp = datetime.strptime(
            parsed.requestedAt, "%Y-%m-%dT%H:%M:%S.%fZ"
        ).replace(tzinfo=timezone.utc)
        age = ((now or datetime.now(timezone.utc)) - timestamp).total_seconds()
        if age < -30 or age > 120:
            raise ValueError("timestamp")
        return result
    except (ValueError, TypeError, UnicodeError, AttributeError):
        raise HelperError("INVALID_REQUEST", 400) from None


def request_identifier(value: str) -> str:
    try:
        parsed = UUID(value)
        if str(parsed) != value:
            raise ValueError()
        return value
    except ValueError:
        raise HelperError("INVALID_REQUEST", 400) from None
