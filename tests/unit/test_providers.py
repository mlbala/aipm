"""The providers through the real SDKs, with an in-memory transport (no sockets).

These tests read the exact HTTP request each SDK builds, so they prove what goes over the wire:
no `temperature`, `top_p` or `top_k` for either provider (ARCHITECTURE §14), the API version the
Anthropic SDK sends, the output cap, the schema, and the endpoint (config only, never `*_BASE_URL`).
"""

import json
from collections.abc import Callable
from email.utils import parsedate_to_datetime
from typing import Any

import httpx2
import pytest

from aipm.config.schema import LlmConfig, Provider
from aipm.domain.errors import ExitCode, UsageError
from aipm.domain.models import RoleName
from aipm.llm.errors import ProviderError, RetryableProviderError, UnsupportedStructuredOutput
from aipm.llm.gateway import NO_KEY_PLACEHOLDER, api_key, make_provider
from aipm.llm.providers.anthropic import AnthropicProvider
from aipm.llm.providers.base import (
    ProviderRequest,
    Stop,
    StructuredMode,
    parse_retry_after,
)
from aipm.llm.providers.openai_compat import OpenAICompatProvider
from aipm.llm.structured import wire_schema
from aipm.roles.interviewer import InterviewRound

SAMPLING = ("temperature", "top_p", "top_k")
SCHEMA_MODE = StructuredMode.JSON_SCHEMA
KEY = "aipm-fake-provider-key-not-real-0042"
SCHEMA = wire_schema(InterviewRound)

type Handler = Callable[[httpx2.Request], httpx2.Response]


class Recorder:
    """A mock transport handler that records requests and replies from a queue."""

    def __init__(self, *responses: httpx2.Response) -> None:
        self.requests: list[httpx2.Request] = []
        self.responses = list(responses)

    def __call__(self, request: httpx2.Request) -> httpx2.Response:
        self.requests.append(request)
        return self.responses.pop(0)

    def body(self, index: int = 0) -> dict[str, Any]:
        return json.loads(self.requests[index].content)


def client(recorder: Recorder) -> httpx2.Client:
    return httpx2.Client(transport=httpx2.MockTransport(recorder))


def request(mode: StructuredMode = StructuredMode.JSON_SCHEMA) -> ProviderRequest:
    return ProviderRequest(
        role=RoleName.INTERVIEWER,
        model="test-model",
        system="system text",
        user="user text",
        max_output_tokens=4321,
        schema_name="InterviewRound",
        schema=SCHEMA,
        mode=mode,
    )


def anthropic_reply(text: str = '{"ok": true}', stop: str = "end_turn") -> httpx2.Response:
    return httpx2.Response(
        200,
        json={
            "id": "msg_01",
            "type": "message",
            "role": "assistant",
            "model": "test-model",
            "content": [
                {"type": "thinking", "thinking": "", "signature": "sig"},
                {"type": "text", "text": text},
            ],
            "stop_reason": stop,
            "stop_sequence": None,
            "usage": {
                "input_tokens": 11,
                "output_tokens": 7,
                "cache_read_input_tokens": 2,
                "cache_creation_input_tokens": None,
            },
        },
    )


def openai_reply(
    text: str | None = '{"ok": true}', finish: str = "stop", refusal: str | None = None,
    usage: bool = True,
) -> httpx2.Response:  # fmt: skip
    body: dict[str, Any] = {
        "id": "chatcmpl-1",
        "object": "chat.completion",
        "created": 1,
        "model": "test-model",
        "choices": [
            {
                "index": 0,
                "message": {"role": "assistant", "content": text, "refusal": refusal},
                "finish_reason": finish,
            }
        ],
    }
    if usage:
        body["usage"] = {"prompt_tokens": 13, "completion_tokens": 5, "total_tokens": 18}
    return httpx2.Response(200, json=body)


def error(
    status: int, message: str = "boom", headers: dict[str, str] | None = None
) -> httpx2.Response:
    return httpx2.Response(
        status, json={"type": "error", "error": {"type": "x", "message": message}}, headers=headers
    )


@pytest.fixture(autouse=True)
def hostile_env(monkeypatch: pytest.MonkeyPatch) -> None:
    """Environment variables that must not redirect or re-key a provider."""
    monkeypatch.setenv("ANTHROPIC_BASE_URL", "https://evil.example/anthropic")
    monkeypatch.setenv("OPENAI_BASE_URL", "https://evil.example/openai")
    monkeypatch.setenv("ANTHROPIC_API_KEY", "aipm-fake-env-key-not-the-one-0043")
    monkeypatch.setenv("OPENAI_API_KEY", "aipm-fake-env-key-not-the-one-0044")


# ---------------------------------------------------------------- anthropic


def test_anthropic_request_on_the_wire() -> None:
    rec = Recorder(anthropic_reply())
    provider = AnthropicProvider(api_key=KEY, http_client=client(rec))
    response = provider.complete(request())
    (sent,) = rec.requests
    body = rec.body()
    assert str(sent.url) == "https://api.anthropic.com/v1/messages"
    assert sent.headers["anthropic-version"] == "2026-10-21"
    assert KEY in (sent.headers.get("x-api-key", "") + sent.headers.get("authorization", ""))
    for name in SAMPLING:
        assert name not in body
    assert body["model"] == "test-model"
    assert body["max_tokens"] == 4321
    assert body["system"] == "system text"
    assert body["messages"] == [{"role": "user", "content": "user text"}]
    assert body["output_config"] == {"format": {"type": "json_schema", "schema": SCHEMA}}
    assert "tools" not in body
    assert response.text == '{"ok": true}'
    assert response.input_tokens == 13
    assert response.output_tokens == 7
    assert response.stop is Stop.END


def test_anthropic_prompt_mode_sends_no_output_config() -> None:
    rec = Recorder(anthropic_reply())
    AnthropicProvider(api_key=KEY, http_client=client(rec)).complete(request(StructuredMode.PROMPT))
    body = rec.body()
    assert "output_config" not in body
    for name in SAMPLING:
        assert name not in body


def test_anthropic_uses_the_configured_base_url_only() -> None:
    rec = Recorder(anthropic_reply())
    provider = AnthropicProvider(
        api_key=KEY, base_url="https://proxy.example.com", http_client=client(rec)
    )
    provider.complete(request())
    assert str(rec.requests[0].url) == "https://proxy.example.com/v1/messages"
    assert "evil.example" not in repr(provider)


@pytest.mark.parametrize(
    ("stop", "expected"),
    [("refusal", Stop.REFUSAL), ("max_tokens", Stop.MAX_TOKENS), ("end_turn", Stop.END)],
)
def test_anthropic_stop_reasons(stop: str, expected: Stop) -> None:
    rec = Recorder(anthropic_reply(stop=stop))
    assert (
        AnthropicProvider(api_key=KEY, http_client=client(rec)).complete(request()).stop is expected
    )


@pytest.mark.parametrize(
    ("reply", "kind", "retry_after"),
    [
        (error(429, headers={"retry-after": "3"}), RetryableProviderError, 3.0),
        (error(529), RetryableProviderError, None),
        (error(500), RetryableProviderError, None),
        (error(400, "output_config.format: unsupported schema"), UnsupportedStructuredOutput, None),
        (error(400, "messages: too long"), ProviderError, None),
        (error(401), ProviderError, None),
        (error(404), ProviderError, None),
    ],
)
def test_anthropic_error_mapping(
    reply: httpx2.Response, kind: type[Exception], retry_after: float | None
) -> None:
    rec = Recorder(reply)
    with pytest.raises(kind) as info:
        AnthropicProvider(api_key=KEY, http_client=client(rec)).complete(request())
    assert type(info.value) is kind
    if isinstance(info.value, RetryableProviderError):
        assert info.value.retry_after == retry_after
    assert len(rec.requests) == 1  # the SDK does not retry on its own


def test_anthropic_connection_failure_is_retryable() -> None:
    def broken(request: httpx2.Request) -> httpx2.Response:
        raise httpx2.ConnectError("refused", request=request)

    provider = AnthropicProvider(
        api_key=KEY, http_client=httpx2.Client(transport=httpx2.MockTransport(broken))
    )
    with pytest.raises(RetryableProviderError, match="could not connect"):
        provider.complete(request())


def test_anthropic_timeout_is_retryable() -> None:
    def slow(request: httpx2.Request) -> httpx2.Response:
        raise httpx2.ReadTimeout("slow", request=request)

    provider = AnthropicProvider(
        api_key=KEY, http_client=httpx2.Client(transport=httpx2.MockTransport(slow))
    )
    with pytest.raises(RetryableProviderError, match="timed out"):
        provider.complete(request())


# ---------------------------------------------------------------- openai-compatible


@pytest.mark.parametrize(
    ("base_url", "url", "cap"),
    [
        (None, "https://api.openai.com/v1/chat/completions", "max_completion_tokens"),
        ("http://localhost:11434/v1", "http://localhost:11434/v1/chat/completions", "max_tokens"),
    ],
)
def test_openai_request_on_the_wire(base_url: str | None, url: str, cap: str) -> None:
    rec = Recorder(openai_reply())
    provider = OpenAICompatProvider(api_key=KEY, base_url=base_url, http_client=client(rec))
    response = provider.complete(request())
    (sent,) = rec.requests
    body = rec.body()
    assert str(sent.url) == url
    assert sent.headers["authorization"] == f"Bearer {KEY}"
    for name in SAMPLING:
        assert name not in body
    assert body[cap] == 4321
    assert ({"max_tokens", "max_completion_tokens"} - {cap}).isdisjoint(body)
    assert body["messages"] == [
        {"role": "system", "content": "system text"},
        {"role": "user", "content": "user text"},
    ]
    assert body["response_format"] == {
        "type": "json_schema",
        "json_schema": {"name": "InterviewRound", "schema": SCHEMA, "strict": True},
    }
    assert "tools" not in body
    assert response.text == '{"ok": true}'
    assert (response.input_tokens, response.output_tokens) == (13, 5)


@pytest.mark.parametrize(
    ("mode", "expected"),
    [(StructuredMode.JSON_OBJECT, {"type": "json_object"}), (StructuredMode.PROMPT, None)],
)
def test_openai_fallback_modes(mode: StructuredMode, expected: dict[str, str] | None) -> None:
    rec = Recorder(openai_reply())
    OpenAICompatProvider(api_key=KEY, http_client=client(rec)).complete(request(mode))
    body = rec.body()
    assert body.get("response_format") == expected
    for name in SAMPLING:
        assert name not in body


@pytest.mark.parametrize(
    ("reply", "stop"),
    [
        (openai_reply(text=None, refusal="I can't help with that"), Stop.REFUSAL),
        (openai_reply(finish="content_filter"), Stop.REFUSAL),
        (openai_reply(finish="length"), Stop.MAX_TOKENS),
    ],
)
def test_openai_stops(reply: httpx2.Response, stop: Stop) -> None:
    rec = Recorder(reply)
    assert (
        OpenAICompatProvider(api_key=KEY, http_client=client(rec)).complete(request()).stop is stop
    )


def test_openai_without_usage_is_charged_an_estimate() -> None:
    rec = Recorder(openai_reply(usage=False))
    response = OpenAICompatProvider(api_key=KEY, http_client=client(rec)).complete(request())
    assert response.input_tokens > 0
    assert response.output_tokens > 0


def test_openai_no_choices_is_an_error() -> None:
    reply = openai_reply()
    body = json.loads(reply.content)
    body["choices"] = []
    rec = Recorder(httpx2.Response(200, json=body))
    with pytest.raises(ProviderError, match="no choices"):
        OpenAICompatProvider(api_key=KEY, http_client=client(rec)).complete(request())


@pytest.mark.parametrize(
    ("reply", "mode", "kind"),
    [
        (error(429, headers={"retry-after-ms": "1500"}), SCHEMA_MODE, RetryableProviderError),
        (error(503), SCHEMA_MODE, RetryableProviderError),
        (error(400, "response_format json_schema is not supported"), SCHEMA_MODE,
         UnsupportedStructuredOutput),
        (error(422, "json_object unsupported"), StructuredMode.JSON_OBJECT,
         UnsupportedStructuredOutput),
        (error(400, "response_format bad"), StructuredMode.PROMPT, ProviderError),
        (error(403), StructuredMode.JSON_SCHEMA, ProviderError),
        (error(404), StructuredMode.JSON_SCHEMA, ProviderError),
    ],
)  # fmt: skip
def test_openai_error_mapping(
    reply: httpx2.Response, mode: StructuredMode, kind: type[Exception]
) -> None:
    rec = Recorder(reply)
    with pytest.raises(kind) as info:
        OpenAICompatProvider(api_key=KEY, http_client=client(rec)).complete(request(mode))
    assert type(info.value) is kind
    assert len(rec.requests) == 1


def test_openai_connection_and_timeout_are_retryable() -> None:
    def broken(request: httpx2.Request) -> httpx2.Response:
        raise httpx2.ConnectError("refused", request=request)

    def slow(request: httpx2.Request) -> httpx2.Response:
        raise httpx2.ReadTimeout("slow", request=request)

    for handler, match in ((broken, "could not connect"), (slow, "timed out")):
        transport = httpx2.Client(transport=httpx2.MockTransport(handler))
        with pytest.raises(RetryableProviderError, match=match):
            OpenAICompatProvider(api_key=KEY, http_client=transport).complete(request())


# ---------------------------------------------------------------- keys and factory


def test_api_key_comes_from_the_named_variable() -> None:
    llm = LlmConfig(api_key_env="MY_KEY")
    assert api_key(llm, {"MY_KEY": KEY}) == KEY
    with pytest.raises(UsageError) as info:
        api_key(llm, {})
    assert info.value.exit_code is ExitCode.USAGE
    assert KEY not in info.value.message


def test_openai_compatible_never_sends_the_anthropic_key() -> None:
    llm = LlmConfig(provider=Provider.OPENAI_COMPATIBLE, base_url="https://api.example.com/v1")
    with pytest.raises(UsageError, match="will not send ANTHROPIC_API_KEY"):
        api_key(llm, {"ANTHROPIC_API_KEY": KEY})


def test_loopback_server_needs_no_key() -> None:
    llm = LlmConfig(provider=Provider.OPENAI_COMPATIBLE, base_url="http://127.0.0.1:11434/v1",
                    api_key_env="OLLAMA_KEY")  # fmt: skip
    assert api_key(llm, {}) == NO_KEY_PLACEHOLDER
    remote = llm.model_copy(update={"base_url": "https://ollama.example.com/v1"})
    with pytest.raises(UsageError):
        api_key(remote, {})


def test_make_provider_picks_the_configured_provider() -> None:
    anthropic = make_provider(LlmConfig(api_key_env="K"), environ={"K": KEY})
    assert isinstance(anthropic, AnthropicProvider)
    assert anthropic.base_url == "https://api.anthropic.com"
    compat = make_provider(
        LlmConfig(provider=Provider.OPENAI_COMPATIBLE, base_url="http://localhost:11434/v1",
                  api_key_env="K"),
        environ={},
    )  # fmt: skip
    assert isinstance(compat, OpenAICompatProvider)
    assert compat.base_url == "http://localhost:11434/v1"


@pytest.mark.parametrize(
    ("headers", "expected"),
    [
        (None, None),
        ({}, None),
        ({"retry-after": "2"}, 2.0),
        ({"retry-after-ms": "250"}, 0.25),
        ({"retry-after-ms": "junk", "retry-after": "4"}, 4.0),
        ({"retry-after": "-1"}, None),
        ({"retry-after": "nan"}, None),
        ({"retry-after": "999999"}, None),
        ({"retry-after": "not a date"}, None),
        ({"retry-after": "Wed, 21 Oct 2026 07:28:00 GMT"}, 30.0),
    ],
)
def test_parse_retry_after(headers: dict[str, str] | None, expected: float | None) -> None:
    now = parsedate_to_datetime("Wed, 21 Oct 2026 07:27:30 GMT").timestamp()
    assert parse_retry_after(headers, now=now) == expected
