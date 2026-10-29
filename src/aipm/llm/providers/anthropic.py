"""The Anthropic provider (ARCHITECTURE §14).

Uses the official `anthropic` SDK (>=2.0.0, which sends API version 2026-10-21 by itself; aipm
sets no `anthropic-version` header), imported lazily at call time. The request carries the model,
`max_tokens`, the system prompt, one user message and, in schema mode, `output_config.format`.
It never carries `temperature`, `top_p` or `top_k`, which that API version rejects.

The client gets the key, the base URL and the timeout explicitly, so `ANTHROPIC_BASE_URL` or a
credential profile on disk cannot redirect it. SDK retries are off (the gateway retries), and so
is the SDK's OpenTelemetry instrumentation (aipm has no telemetry, AGENTS.md rule 10).
"""

from typing import TYPE_CHECKING, Any

from aipm.llm.errors import (
    ProviderError,
    RetryableProviderError,
    UnsupportedStructuredOutput,
)
from aipm.llm.providers.base import (
    TIMEOUT_S,
    ProviderRequest,
    ProviderResponse,
    Stop,
    StructuredMode,
    mentions_structured_output,
    parse_retry_after,
    short_message,
)

if TYPE_CHECKING:
    import anthropic

DEFAULT_BASE_URL = "https://api.anthropic.com"
_KEY_HINT = "Check the key in the variable named by llm.api_key_env."


class AnthropicProvider:
    """Call the Messages API with structured output."""

    name = "anthropic"
    modes: tuple[StructuredMode, ...] = (StructuredMode.JSON_SCHEMA, StructuredMode.PROMPT)

    def __init__(
        self,
        *,
        api_key: str,
        base_url: str | None = None,
        timeout_s: float = TIMEOUT_S,
        http_client: Any = None,
    ) -> None:
        self._api_key = api_key
        self.base_url = base_url or DEFAULT_BASE_URL
        self.timeout_s = timeout_s
        self._http_client = http_client
        self._client: anthropic.Anthropic | None = None

    def __repr__(self) -> str:
        return f"AnthropicProvider(base_url={self.base_url!r})"

    def _sdk(self) -> "anthropic.Anthropic":
        if self._client is None:
            import anthropic

            self._client = anthropic.Anthropic(
                api_key=self._api_key,
                base_url=self.base_url,
                timeout=self.timeout_s,
                max_retries=0,
                open_telemetry=False,
                http_client=self._http_client,
            )
        return self._client

    def complete(self, request: ProviderRequest) -> ProviderResponse:
        """Send one Messages request and return the text blocks joined."""
        import anthropic

        client = self._sdk()
        output_config: anthropic.types.OutputConfigParam | anthropic.Omit = anthropic.omit
        if request.mode is StructuredMode.JSON_SCHEMA:
            output_config = {"format": {"type": "json_schema", "schema": dict(request.schema)}}
        try:
            message = client.messages.create(
                model=request.model,
                max_tokens=request.max_output_tokens,
                system=request.system,
                messages=[{"role": "user", "content": request.user}],
                output_config=output_config,
            )
        except anthropic.APITimeoutError:
            raise RetryableProviderError("the Anthropic API timed out") from None
        except anthropic.APIConnectionError:
            raise RetryableProviderError("could not connect to the Anthropic API") from None
        except anthropic.RateLimitError as exc:
            raise RetryableProviderError(
                "rate limited by the Anthropic API (429)",
                retry_after=parse_retry_after(exc.response.headers),
            ) from None
        except anthropic.BadRequestError as exc:
            detail = short_message(exc.message)
            if request.mode is StructuredMode.JSON_SCHEMA and mentions_structured_output(detail):
                raise UnsupportedStructuredOutput(f"structured output rejected: {detail}") from None
            raise ProviderError(f"the Anthropic API rejected the request (400): {detail}") from None
        except (anthropic.AuthenticationError, anthropic.PermissionDeniedError) as exc:
            raise ProviderError(
                f"the Anthropic API refused the credentials ({exc.status_code})", hint=_KEY_HINT
            ) from None
        except anthropic.APIStatusError as exc:
            if exc.status_code >= 500 or exc.status_code == 408:
                raise RetryableProviderError(
                    f"the Anthropic API failed ({exc.status_code})",
                    retry_after=parse_retry_after(exc.response.headers),
                ) from None
            raise ProviderError(
                f"the Anthropic API returned {exc.status_code}: {short_message(exc.message)}"
            ) from None
        text = "".join(block.text for block in message.content if block.type == "text")
        if message.stop_reason == "refusal":
            stop = Stop.REFUSAL
        elif message.stop_reason in ("max_tokens", "model_context_window_exceeded"):
            stop = Stop.MAX_TOKENS
        else:
            stop = Stop.END
        usage = message.usage
        input_tokens = (
            usage.input_tokens
            + (usage.cache_creation_input_tokens or 0)
            + (usage.cache_read_input_tokens or 0)
        )
        return ProviderResponse(
            text=text, input_tokens=input_tokens, output_tokens=usage.output_tokens, stop=stop
        )
