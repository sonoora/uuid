import json
from datetime import datetime, timezone
from typing import Annotated, Literal
from uuid import UUID
from pydantic import BaseModel, ConfigDict, Field, StringConstraints, field_validator
from .errors import HelperError

Text = Annotated[
    str, StringConstraints(min_length=1, max_length=160, pattern=r"^[^\x00-\x1f]+$")
]
Identifier = Annotated[
    str,
    StringConstraints(
        pattern=r"^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$"
    ),
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


class Metadata(Strict):
    name: Text
    refId: Text


class CreateCommand(Strict):
    type: Literal["wallet.create"]
    accountType: Literal["SCA"]
    blockchains: Annotated[list[Text], Field(min_length=1, max_length=1)]
    count: Literal[1]
    walletSetId: ProviderIdentifier
    metadata: Annotated[list[Metadata], Field(min_length=1, max_length=1)]


class TransferCommand(Strict):
    type: Literal["token.transfer", "wallet.deploy"]
    walletId: ProviderIdentifier
    blockchain: Text
    tokenAddress: Address
    destinationAddress: Address
    amounts: Annotated[list[Amount], Field(min_length=1, max_length=1)]
    feeLevel: Literal["LOW", "MEDIUM", "HIGH"]
    refId: Text


class Actor(Strict):
    type: Literal["user", "automation"]
    reference: Text


class Business(Strict):
    userId: Text | None = None
    profileId: Text | None = None
    linkId: Text | None = None
    transferIntentId: Text | None = None


class Context(Strict):
    operationId: Identifier
    environment: Literal["dev", "prod"]
    circleAccountRef: Text
    purpose: Literal[
        "wallet_create",
        "wallet_deploy",
        "money_transfer",
        "cashback",
        "deposit_fee",
        "distribution",
        "move",
        "remediation",
    ]
    actor: Actor
    business: Business
    providerIdempotencyKey: Identifier
    command: Annotated[CreateCommand | TransferCommand, Field(discriminator="type")]


class Envelope(Strict):
    schemaVersion: Literal["uuid-context-v1"]
    requestId: Identifier
    attemptId: Identifier
    requestedAt: str
    context: Context

    @field_validator("requestedAt")
    @classmethod
    def timestamp(cls, value):
        # One wire representation shared with Date.toISOString().
        parsed = datetime.strptime(value, "%Y-%m-%dT%H:%M:%S.%fZ")
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
        # Reject noncanonical IDs, illegal Unicode and implicit numeric coercion.
        json.dumps(result, ensure_ascii=False).encode("utf-8")
        if isinstance(obj.get("context", {}).get("command", {}).get("count"), bool):
            raise ValueError("count")
        timestamp = datetime.strptime(
            parsed.requestedAt, "%Y-%m-%dT%H:%M:%S.%fZ"
        ).replace(tzinfo=timezone.utc)
        age = ((now or datetime.now(timezone.utc)) - timestamp).total_seconds()
        if age < -30 or age > 120:
            raise ValueError("timestamp")
        command = result["context"]["command"]
        if command["type"] != "wallet.create":
            from decimal import Decimal

            amount = Decimal(command["amounts"][0])
            if (command["type"] == "wallet.deploy" and amount != 0) or (
                command["type"] == "token.transfer" and amount <= 0
            ):
                raise ValueError("amount")
        return result
    except (ValueError, TypeError, UnicodeError, AttributeError):
        raise HelperError("INVALID_REQUEST", 400) from None


def request_identifier(value: str) -> str:
    try:
        parsed = UUID(value)
        if parsed.version != 4 or str(parsed) != value:
            raise ValueError()
        return value
    except ValueError:
        raise HelperError("INVALID_REQUEST", 400) from None
