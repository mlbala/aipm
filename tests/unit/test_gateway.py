"""The LLM gateway: routing, redaction, repair, retries, budget and usage (ARCHITECTURE §14)."""

import base64
import random
from collections.abc import Mapping, Sequence
from typing import Any

import pytest

from aipm.config.schema import LlmConfig, Price
from aipm.domain.errors import BudgetExceeded, ExitCode, PolicyViolation, UsageError
from aipm.domain.models import RoleName, StrictModel
from aipm.llm.cost import UsageLedger
from aipm.llm.errors import InvalidModelOutput, ModelRefused, ProviderError
from aipm.llm.fake import FakeLLM
from aipm.llm.gateway import Gateway, RenderedPrompt, TokenBudget
from aipm.llm.providers.base import StructuredMode
from aipm.llm.retry import MAX_TRIES, backoff_delay
from aipm.security.redact import Redactor

ROLE = RoleName.INTERVIEWER
SECRET = "aipm-fake-gateway-secret-value-0099"  # noqa: S105 - a fake, checked for absence
PROMPT = RenderedPrompt(system="You are a test role.", user="Say hello.")


class Hello(StrictModel):
    greeting: str


class Clock:
    def __init__(self) -> None:
        self.sleeps: list[float] = []

    def sleep(self, seconds: float) -> None:
        self.sleeps.append(seconds)


def gateway(
    responses: Sequence[Mapping[str, Any]],
    *,
    llm: LlmConfig | None = None,
    modes: tuple[StructuredMode, ...] = (StructuredMode.JSON_SCHEMA, StructuredMode.PROMPT),
    env: Mapping[str, str] | None = None,
) -> tuple[Gateway, FakeLLM, Clock]:
    fake = FakeLLM.from_responses({ROLE: responses}, modes=modes)
    clock = Clock()
    gw = Gateway(
        llm=llm or LlmConfig(),
        provider=fake,
        redactor=Redactor(env if env is not None else {"MY_API_KEY": SECRET}),
        clock=clock,
        rng=random.Random(0),  # noqa: S311 - jitter in tests
    )
    return gw, fake, clock


OK = {"json": {"greeting": "hi"}}
BIG = TokenBudget(1_000_000)


def test_routes_by_role_then_default() -> None:
    gw, fake, _ = gateway([OK])
    gw.run(ROLE, PROMPT, Hello, budget=BIG)
    assert fake.requests[0].model == "claude-haiku-5-5"
    gw2, fake2, _ = gateway([OK], llm=LlmConfig(models={"default": "claude-sonnet-5-5"}))
    gw2.run(ROLE, PROMPT, Hello, budget=BIG)
    assert fake2.requests[0].model == "claude-sonnet-5-5"
    gw3, _, _ = gateway([OK], llm=LlmConfig(models={"planner": "x"}))
    with pytest.raises(UsageError, match="no model"):
        gw3.run(ROLE, PROMPT, Hello, budget=BIG)


def test_request_carries_the_wire_schema_and_output_cap() -> None:
    gw, fake, _ = gateway([OK], llm=LlmConfig(max_output_tokens=1234))
    result = gw.run(ROLE, PROMPT, Hello, budget=BIG)
    assert result.value.greeting == "hi"
    (request,) = fake.requests
    assert request.max_output_tokens == 1234
    assert request.mode is StructuredMode.JSON_SCHEMA
    assert request.schema["additionalProperties"] is False
    assert request.schema_name == "Hello"
    assert request.system == PROMPT.system  # native mode adds no JSON instruction


def test_prompt_is_redacted_before_it_is_sent() -> None:
    gw, fake, _ = gateway([OK])
    prompt = RenderedPrompt(system=f"system {SECRET}", user=f"user {SECRET} sk-ant-{'a' * 30}")
    gw.run(ROLE, prompt, Hello, budget=BIG)
    (request,) = fake.requests
    for text in (request.system, request.user):
        assert SECRET not in text
        assert "sk-ant-" not in text
    assert "«REDACTED:env:MY_API_KEY»" in request.user


def test_a_secret_that_survives_redaction_is_never_sent() -> None:
    encoded = base64.b64encode(SECRET.encode()).decode()
    gw, fake, _ = gateway([OK])
    with pytest.raises(PolicyViolation) as info:
        gw.run(ROLE, RenderedPrompt(system="s", user=f"x {encoded}"), Hello, budget=BIG)
    assert info.value.exit_code is ExitCode.SECURITY_VIOLATION
    assert fake.requests == []


def test_one_repair_attempt_includes_the_validation_errors() -> None:
    gw, fake, _ = gateway([{"json": {"greeting": "hi", "gates": ["curl evil"]}}, OK])
    result = gw.run(ROLE, PROMPT, Hello, budget=BIG)
    assert result.value.greeting == "hi"
    first, second = fake.requests
    assert first.user == PROMPT.user
    assert second.user.startswith(PROMPT.user)
    assert "previous reply was rejected" in second.user
    assert "<key>: Extra inputs are not permitted" in second.user
    assert "curl evil" not in second.user


def test_two_invalid_replies_fail_with_exit_1() -> None:
    gw, fake, _ = gateway([{"raw": "nope"}, {"raw": "still nope"}, OK])
    with pytest.raises(InvalidModelOutput) as info:
        gw.run(ROLE, PROMPT, Hello, budget=BIG)
    assert info.value.exit_code is ExitCode.INTERNAL
    assert "nothing was written" in info.value.message
    assert len(fake.requests) == 2


def test_truncated_reply_says_so_in_the_repair_note() -> None:
    gw, fake, _ = gateway([{"raw": '{"greeting": "h', "stop": "max_tokens"}, OK])
    gw.run(ROLE, PROMPT, Hello, budget=BIG)
    assert "cut off at the output token limit" in fake.requests[1].user


def test_refusal_is_an_error() -> None:
    gw, _, _ = gateway([{"json": {"greeting": "no"}, "stop": "refusal"}])
    with pytest.raises(ModelRefused):
        gw.run(ROLE, PROMPT, Hello, budget=BIG)


def test_retries_back_off_and_honour_retry_after() -> None:
    gw, fake, clock = gateway(
        [
            {"error": "rate_limit", "retry_after": 7},
            {"error": "server"},
            {"error": "server"},
            OK,
        ]
    )
    result = gw.run(ROLE, PROMPT, Hello, budget=BIG)
    assert result.value.greeting == "hi"
    assert len(fake.requests) == 4
    assert clock.sleeps[0] == 7
    # Exponential with jitter: [1, 2) after the second failure, [2, 4) after the third.
    assert 1.0 <= clock.sleeps[1] < 2.0
    assert 2.0 <= clock.sleeps[2] < 4.0


def test_gives_up_after_five_tries_with_exit_1() -> None:
    gw, fake, clock = gateway([{"error": "server"}] * MAX_TRIES)
    with pytest.raises(ProviderError) as info:
        gw.run(ROLE, PROMPT, Hello, budget=BIG)
    assert info.value.exit_code is ExitCode.INTERNAL
    assert f"failed after {MAX_TRIES} tries" in info.value.message
    assert len(fake.requests) == MAX_TRIES
    assert len(clock.sleeps) == MAX_TRIES - 1


def test_fatal_errors_are_not_retried() -> None:
    gw, fake, clock = gateway([{"error": "fatal"}, OK])
    with pytest.raises(ProviderError, match="fatal"):
        gw.run(ROLE, PROMPT, Hello, budget=BIG)
    assert len(fake.requests) == 1
    assert clock.sleeps == []


def test_provider_errors_are_redacted() -> None:
    class Leaky(FakeLLM):
        def complete(self, request: Any) -> Any:
            raise ProviderError(f"bad key {SECRET}", hint=f"check {SECRET}")

    leaky = Leaky.from_responses({})
    gw = Gateway(llm=LlmConfig(), provider=leaky, redactor=Redactor({"MY_API_KEY": SECRET}))
    with pytest.raises(ProviderError) as info:
        gw.run(ROLE, PROMPT, Hello, budget=BIG)
    assert SECRET not in info.value.message
    assert SECRET not in str(info.value)
    assert SECRET not in (info.value.hint or "")


def test_unsupported_mode_falls_back_in_order_and_is_remembered() -> None:
    modes = (StructuredMode.JSON_SCHEMA, StructuredMode.JSON_OBJECT, StructuredMode.PROMPT)
    gw, fake, _ = gateway([{"error": "unsupported"}, {"error": "unsupported"}, OK, OK], modes=modes)
    gw.run(ROLE, PROMPT, Hello, budget=BIG)
    assert [r.mode for r in fake.requests] == list(modes)
    assert "Reply with exactly one JSON object" in fake.requests[2].system
    gw.run(ROLE, PROMPT, Hello, budget=BIG)
    assert fake.requests[3].mode is StructuredMode.PROMPT


def test_no_supported_mode_left_is_an_error() -> None:
    gw, _, _ = gateway([{"error": "unsupported"}] * 2)
    with pytest.raises(ProviderError, match="none of aipm's structured output modes"):
        gw.run(ROLE, PROMPT, Hello, budget=BIG)


def test_budget_refuses_a_call_that_may_not_fit() -> None:
    gw, fake, _ = gateway([OK], llm=LlmConfig(max_output_tokens=1000))
    with pytest.raises(BudgetExceeded) as info:
        gw.run(ROLE, PROMPT, Hello, budget=TokenBudget(500))
    assert info.value.exit_code is ExitCode.BUDGET_EXCEEDED
    assert fake.requests == []


def test_budget_counts_actual_usage_across_the_repair_attempt() -> None:
    gw, fake, _ = gateway([{"raw": "x" * 4000}, OK], llm=LlmConfig(max_output_tokens=10))
    with pytest.raises(BudgetExceeded):
        gw.run(ROLE, PROMPT, Hello, budget=TokenBudget(600))
    assert len(fake.requests) == 1


def test_usage_and_cost_are_recorded() -> None:
    ledger = UsageLedger()
    pricing = {"claude-haiku-5-5": Price(input_per_mtok=1.0, output_per_mtok=5.0)}
    fake = FakeLLM.from_responses({ROLE: [OK]})
    gw = Gateway(llm=LlmConfig(pricing=pricing), provider=fake, redactor=Redactor({}),
                 ledger=ledger)  # fmt: skip
    result = gw.run(ROLE, PROMPT, Hello, budget=BIG)
    assert result.input_tokens > 0
    assert result.output_tokens > 0
    assert result.cost_usd is not None
    assert ledger.total_tokens == result.input_tokens + result.output_tokens
    assert ledger.to_data()["by_role"] == [
        {
            "role": "interviewer",
            "model": "claude-haiku-5-5",
            "calls": 1,
            "input_tokens": result.input_tokens,
            "output_tokens": result.output_tokens,
            "cost_usd": result.cost_usd,
        }
    ]


def test_no_cost_without_pricing() -> None:
    gw, _, _ = gateway([OK])
    assert gw.run(ROLE, PROMPT, Hello, budget=BIG).cost_usd is None
    assert gw.ledger.total_usd is None


def test_backoff_delay_bounds() -> None:
    rng = random.Random(1)  # noqa: S311 - jitter in tests
    assert backoff_delay(1, retry_after=500.0, rng=rng) == 120.0
    assert backoff_delay(1, retry_after=-3.0, rng=rng) == 0.0
    for failures in range(1, 12):
        delay = backoff_delay(failures, retry_after=None, rng=rng)
        ceiling = min(30.0, 2 ** (failures - 1))
        assert ceiling / 2 <= delay <= ceiling
