"""What the gateway sends a provider, what it gets back, and the provider protocol.

Providers never see a template or an `Untrusted` value: they get the final, redacted system and
user text plus the wire schema, and return the raw text for the gateway to validate.
"""

import email.utils
import math
import time
from collections.abc import Mapping
from dataclasses import dataclass
from enum import StrEnum
from typing import Any, Protocol

from aipm.domain.models import RoleName

TIMEOUT_S = 120.0
"""Per-request timeout (ARCHITECTURE §14)."""

_FORMAT_WORDS = (
    "output_config",
    "output_format",
    "response_format",
    "json_schema",
    "json_object",
    "structured output",
)


class StructuredMode(StrEnum):
    """How the provider is asked for JSON (ADR-0014). Every mode ends in the same validation."""

    JSON_SCHEMA = "json_schema"
    JSON_OBJECT = "json_object"
    PROMPT = "prompt"


class Stop(StrEnum):
    """Why the model stopped."""

    END = "end"
    MAX_TOKENS = "max_tokens"
    REFUSAL = "refusal"


@dataclass(frozen=True, slots=True)
class ProviderRequest:
    """One call. `role` is metadata for routing and fakes; it is never sent."""

    role: RoleName
    model: str
    system: str
    user: str
    max_output_tokens: int
    schema_name: str
    schema: Mapping[str, Any]
    mode: StructuredMode


@dataclass(frozen=True, slots=True)
class ProviderResponse:
    """The raw response text and the token usage the provider reported."""

    text: str
    input_tokens: int
    output_tokens: int
    stop: Stop = Stop.END


class Provider(Protocol):
    """An LLM provider: one request in, raw text out. Raises `aipm.llm.errors` types."""

    name: str
    modes: tuple[StructuredMode, ...]

    def complete(self, request: ProviderRequest) -> ProviderResponse:
        """Send the request and return the raw response."""
        ...


def parse_retry_after(
    headers: Mapping[str, str] | None, *, now: float | None = None
) -> float | None:
    """Seconds to wait from `retry-after-ms` or `retry-after` (seconds or an HTTP date)."""
    if headers is None:
        return None
    millis = headers.get("retry-after-ms")
    if millis:
        try:
            value = float(millis) / 1000
        except ValueError:
            value = -1.0
        if 0 <= value < 86_400:
            return value
    raw = headers.get("retry-after")
    if not raw:
        return None
    try:
        value = float(raw)
    except ValueError:
        try:
            when = email.utils.parsedate_to_datetime(raw)
        except (TypeError, ValueError, IndexError):
            return None
        value = when.timestamp() - (time.time() if now is None else now)
    if math.isnan(value) or value < 0 or value >= 86_400:  # NaN, negative or absurd
        return None
    return value


def mentions_structured_output(message: str) -> bool:
    """Whether a 400/422 message is about the structured-output parameters themselves."""
    lowered = message.lower()
    return any(word in lowered for word in _FORMAT_WORDS)


def short_message(message: object, limit: int = 300) -> str:
    """A provider message, single line and capped; the gateway redacts it afterwards."""
    text = " ".join(str(message).split())
    return text if len(text) <= limit else text[: limit - 1] + "…"
