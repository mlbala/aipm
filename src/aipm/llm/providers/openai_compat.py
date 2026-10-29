"""The openai-compatible provider: the official `openai` SDK with `base_url` (ARCHITECTURE §14).

Covers OpenAI, Azure OpenAI, OpenRouter, Ollama, vLLM and LM Studio. The SDK is imported lazily.
The request carries the model, a system and a user message, the output token cap and the
`response_format`; never `temperature`, `top_p` or `top_k`.

The output cap is `max_completion_tokens` on api.openai.com (its reasoning models reject
`max_tokens`) and `max_tokens` on any other server, which is what Ollama and vLLM document.
The client gets the key and the base URL explicitly, so `OPENAI_BASE_URL` cannot redirect it.
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
    import openai
    from openai.types.chat.completion_create_params import ResponseFormat

DEFAULT_BASE_URL = "https://api.openai.com/v1"
_KEY_HINT = "Check the key in the variable named by llm.api_key_env."


class OpenAICompatProvider:
    """Call a Chat Completions-compatible endpoint with structured output."""

    name = "openai-compatible"
    modes: tuple[StructuredMode, ...] = (
        StructuredMode.JSON_SCHEMA,
        StructuredMode.JSON_OBJECT,
        StructuredMode.PROMPT,
    )

    def __init__(
        self,
        *,
        api_key: str,
        base_url: str | None = None,
        timeout_s: float = TIMEOUT_S,
        http_client: Any = None,
    ) -> None:
        self._api_key = api_key
        self.official = base_url is None
        self.base_url = base_url or DEFAULT_BASE_URL
        self.timeout_s = timeout_s
        self._http_client = http_client
        self._client: openai.OpenAI | None = None

    def __repr__(self) -> str:
        return f"OpenAICompatProvider(base_url={self.base_url!r})"

    def _sdk(self) -> "openai.OpenAI":
        if self._client is None:
            import openai

            self._client = openai.OpenAI(
                api_key=self._api_key,
                base_url=self.base_url,
                timeout=self.timeout_s,
                max_retries=0,
                http_client=self._http_client,
            )
        return self._client

    def _response_format(self, request: ProviderRequest) -> "ResponseFormat | openai.Omit":
        import openai

        if request.mode is StructuredMode.JSON_SCHEMA:
            return {
                "type": "json_schema",
                "json_schema": {
                    "name": request.schema_name,
                    "schema": dict(request.schema),
                    "strict": True,
                },
            }
        if request.mode is StructuredMode.JSON_OBJECT:
            return {"type": "json_object"}
        return openai.omit

    def complete(self, request: ProviderRequest) -> ProviderResponse:
        """Send one chat completion and return the message text."""
        import openai

        client = self._sdk()
        cap = request.max_output_tokens
        try:
            completion = client.chat.completions.create(
                model=request.model,
                messages=[
                    {"role": "system", "content": request.system},
                    {"role": "user", "content": request.user},
                ],
                max_completion_tokens=cap if self.official else openai.omit,
                max_tokens=openai.omit if self.official else cap,
                response_format=self._response_format(request),
            )
        except openai.APITimeoutError:
            raise RetryableProviderError(f"{self.base_url} timed out") from None
        except openai.APIConnectionError:
            raise RetryableProviderError(f"could not connect to {self.base_url}") from None
        except openai.RateLimitError as exc:
            raise RetryableProviderError(
                f"rate limited by {self.base_url} (429)",
                retry_after=parse_retry_after(exc.response.headers),
            ) from None
        except (openai.BadRequestError, openai.UnprocessableEntityError) as exc:
            detail = short_message(exc.message)
            if request.mode is not StructuredMode.PROMPT and mentions_structured_output(detail):
                raise UnsupportedStructuredOutput(f"structured output rejected: {detail}") from None
            raise ProviderError(
                f"{self.base_url} rejected the request ({exc.status_code}): {detail}"
            ) from None
        except (openai.AuthenticationError, openai.PermissionDeniedError) as exc:
            raise ProviderError(
                f"{self.base_url} refused the credentials ({exc.status_code})", hint=_KEY_HINT
            ) from None
        except openai.APIStatusError as exc:
            if exc.status_code >= 500 or exc.status_code == 408:
                raise RetryableProviderError(
                    f"{self.base_url} failed ({exc.status_code})",
                    retry_after=parse_retry_after(exc.response.headers),
                ) from None
            raise ProviderError(
                f"{self.base_url} returned {exc.status_code}: {short_message(exc.message)}"
            ) from None
        if not completion.choices:
            raise ProviderError(f"{self.base_url} returned no choices")
        choice = completion.choices[0]
        message = choice.message
        if message.refusal or choice.finish_reason == "content_filter":
            stop = Stop.REFUSAL
        elif choice.finish_reason == "length":
            stop = Stop.MAX_TOKENS
        else:
            stop = Stop.END
        text = message.content or ""
        usage = completion.usage
        # A server that reports no usage is charged an estimate, so the budget still holds.
        return ProviderResponse(
            text=text,
            input_tokens=usage.prompt_tokens
            if usage is not None
            else _estimate(request.system + request.user),
            output_tokens=usage.completion_tokens if usage is not None else _estimate(text),
            stop=stop,
        )


def _estimate(text: str) -> int:
    return len(text) // 4 + 1
