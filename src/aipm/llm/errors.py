"""Errors raised by the LLM gateway and its providers (ARCHITECTURE §5.4).

A failed provider call exits 1 with the provider's message, which the gateway redacts before
it reaches a log or the terminal.
"""

from collections.abc import Mapping

from aipm.domain.errors import AipmError


class ProviderError(AipmError):
    """A provider call failed for a reason a retry will not fix."""

    code = "LLM_PROVIDER_ERROR"


class RetryableProviderError(ProviderError):
    """A 429, 5xx, timeout or connection failure; the gateway backs off and tries again."""

    code = "LLM_RETRYABLE"

    def __init__(
        self,
        message: str,
        *,
        retry_after: float | None = None,
        hint: str | None = None,
        data: Mapping[str, object] | None = None,
    ) -> None:
        super().__init__(message, hint=hint, data=data)
        self.retry_after = retry_after


class UnsupportedStructuredOutput(ProviderError):
    """The provider rejected the structured-output mechanism itself (ADR-0014)."""

    code = "LLM_STRUCTURED_OUTPUT_UNSUPPORTED"


class ModelRefused(ProviderError):
    """The model declined the request (a refusal stop reason)."""

    code = "LLM_REFUSED"


class InvalidModelOutput(AipmError):
    """The response failed schema validation, and so did the one repair attempt."""

    code = "LLM_INVALID_OUTPUT"
