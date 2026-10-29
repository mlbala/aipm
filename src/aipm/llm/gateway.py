"""The LLM gateway (C-5, ARCHITECTURE §14): the only place aipm talks to a model.

For each role call it routes the role to a model, redacts the rendered prompt (and refuses to
send it if a secret survives redaction), calls the provider with retries, validates the response
into the role's Pydantic model with one repair attempt, enforces the token budget and records
usage. It never sends `temperature`, `top_p` or `top_k`: no request type carries them.

`make_provider` builds the provider from the user's config; tests replace it with `FakeLLM`, so
the rest of the gateway (redaction, validation, repair, budget) runs unchanged under test.
"""

import logging
import os
import random
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Protocol
from urllib.parse import urlsplit

from pydantic import BaseModel

from aipm.config.schema import LlmConfig
from aipm.config.schema import Provider as ProviderName
from aipm.domain.errors import BudgetExceeded, PolicyViolation, UsageError
from aipm.domain.models import RoleName
from aipm.llm.cost import UsageLedger, usd_cost
from aipm.llm.errors import (
    InvalidModelOutput,
    ModelRefused,
    ProviderError,
    RetryableProviderError,
    UnsupportedStructuredOutput,
)
from aipm.llm.providers.anthropic import AnthropicProvider
from aipm.llm.providers.base import (
    Provider,
    ProviderRequest,
    ProviderResponse,
    Stop,
    StructuredMode,
)
from aipm.llm.providers.openai_compat import OpenAICompatProvider
from aipm.llm.retry import MAX_TRIES, Clock, SystemClock, backoff_delay
from aipm.llm.structured import (
    OutputInvalid,
    json_instruction,
    parse_response,
    repair_note,
    schema_name,
    wire_schema,
)
from aipm.security.redact import Redactor

log = logging.getLogger("aipm.llm")

_LOOPBACK = frozenset({"localhost", "127.0.0.1", "::1"})
NO_KEY_PLACEHOLDER = "aipm-no-key"
"""Sent as the key to a loopback openai-compatible server (Ollama, LM Studio) that needs none."""


@dataclass(frozen=True, slots=True)
class RenderedPrompt:
    """A system prompt plus user content with untrusted parts already wrapped."""

    system: str
    user: str


@dataclass(frozen=True, slots=True)
class TokenBudget:
    """The tokens a call may still spend."""

    remaining_tokens: int


@dataclass(frozen=True, slots=True)
class RoleResult[T]:
    """A validated role output with its usage and cost."""

    value: T
    input_tokens: int
    output_tokens: int
    cost_usd: float | None


class LLMGateway(Protocol):
    """Run one role call."""

    def run[T: BaseModel](
        self, role: RoleName, prompt: RenderedPrompt, schema: type[T], *, budget: TokenBudget
    ) -> RoleResult[T]:
        """Route, redact, call, validate (one repair attempt) and account."""
        ...


@dataclass(slots=True)
class _Meter:
    """Tokens spent by one `run`, against its budget."""

    limit: int
    input_tokens: int = 0
    output_tokens: int = 0
    cost_usd: float | None = None

    @property
    def spent(self) -> int:
        return self.input_tokens + self.output_tokens


def estimate_tokens(text: str) -> int:
    """A rough upper estimate for the budget check: four characters per token."""
    return len(text) // 4 + 1


class Gateway:
    """The `LLMGateway` implementation."""

    def __init__(
        self,
        *,
        llm: LlmConfig,
        provider: Provider,
        redactor: Redactor,
        ledger: UsageLedger | None = None,
        clock: Clock | None = None,
        rng: random.Random | None = None,
    ) -> None:
        self.llm = llm
        self.provider = provider
        self.redactor = redactor
        self.ledger = ledger if ledger is not None else UsageLedger()
        self._clock: Clock = clock if clock is not None else SystemClock()
        self._rng = rng if rng is not None else random.Random()  # noqa: S311 - jitter, not crypto
        self._unsupported: set[StructuredMode] = set()
        self._pricing: dict[str, dict[str, float]] = {
            model: {"input_per_mtok": p.input_per_mtok, "output_per_mtok": p.output_per_mtok}
            for model, p in llm.pricing.items()
        }

    # ------------------------------------------------------------ routing and redaction

    def model_for(self, role: RoleName) -> str:
        """`llm.models.<role>`, falling back to `llm.models.default` (ARCHITECTURE §14)."""
        model = self.llm.models.get(role.value) or self.llm.models.get("default")
        if not model:
            raise UsageError(
                f"no model is configured for the {role.value} role",
                hint="Set llm.models.default (or llm.models.<role>) in your user config.",
            )
        return model

    def _redact(self, text: str, part: str) -> str:
        clean = self.redactor.redact(text)
        if self.redactor.contains_secret(clean):
            raise PolicyViolation(
                f"refusing to send the {part} prompt: it still contains a secret after redaction",
                hint="Remove the secret (or its encoded form) from the input and try again.",
            )
        return clean

    def _redacted_error[E: ProviderError](self, exc: E) -> E:
        exc.message = self.redactor.redact(exc.message)
        exc.args = (exc.message,)
        if exc.hint:
            exc.hint = self.redactor.redact(exc.hint)
        return exc

    # ------------------------------------------------------------ the call

    def run[T: BaseModel](
        self, role: RoleName, prompt: RenderedPrompt, schema: type[T], *, budget: TokenBudget
    ) -> RoleResult[T]:
        """Route, redact, call, validate (one repair attempt) and account."""
        model = self.model_for(role)
        wire = wire_schema(schema)
        system = self._redact(prompt.system, "system")
        user = self._redact(prompt.user, "user")
        meter = _Meter(limit=budget.remaining_tokens)
        problems: list[str] = []
        for attempt in range(2):
            content = user if attempt == 0 else f"{user}\n\n{repair_note(problems)}"
            response = self._call(role, model, system, content, schema_name(schema), wire, meter)
            if response.stop is Stop.REFUSAL:
                raise ModelRefused(
                    f"the model declined the {role.value} request",
                    hint="Rephrase the input, or try another model for this role.",
                )
            try:
                value = parse_response(response.text, schema)
            except OutputInvalid as exc:
                problems = list(exc.problems)
                if response.stop is Stop.MAX_TOKENS:
                    problems.insert(0, "the reply was cut off at the output token limit; be brief")
                log.info("%s reply invalid (try %d): %s", role.value, attempt + 1, problems)
                continue
            return RoleResult(
                value=value,
                input_tokens=meter.input_tokens,
                output_tokens=meter.output_tokens,
                cost_usd=meter.cost_usd,
            )
        raise InvalidModelOutput(
            f"the {role.value} response failed validation twice, so nothing was written: "
            + "; ".join(problems[:3]),
            hint="Run the command again; if it keeps failing, try a stronger model for this role.",
        )

    def _call(
        self,
        role: RoleName,
        model: str,
        system: str,
        user: str,
        name: str,
        wire: Mapping[str, object],
        meter: _Meter,
    ) -> ProviderResponse:
        """Try each structured-output mode the provider still supports, in order (ADR-0014)."""
        for mode in self.provider.modes:
            if mode in self._unsupported:
                continue
            full_system = (
                system
                if mode is StructuredMode.JSON_SCHEMA
                else (f"{system}\n\n{json_instruction(wire)}")
            )
            request = ProviderRequest(
                role=role,
                model=model,
                system=full_system,
                user=user,
                max_output_tokens=self.llm.max_output_tokens,
                schema_name=name,
                schema=wire,
                mode=mode,
            )
            try:
                return self._with_retries(request, meter)
            except UnsupportedStructuredOutput as exc:
                log.warning(
                    "%s rejected %s output (%s); falling back",
                    self.provider.name,
                    mode.value,
                    self.redactor.redact(exc.message),
                )
                self._unsupported.add(mode)
        raise ProviderError(
            f"{self.provider.name} accepts none of aipm's structured output modes",
            hint="Use a model or server that supports JSON output.",
        )

    def _with_retries(self, request: ProviderRequest, meter: _Meter) -> ProviderResponse:
        failures = 0
        while True:
            self._check_budget(request, meter)
            try:
                response = self.provider.complete(request)
            except RetryableProviderError as exc:
                error = self._redacted_error(exc)
                failures += 1
                if failures >= MAX_TRIES:
                    raise ProviderError(
                        f"{self.provider.name} failed after {MAX_TRIES} tries: {error.message}",
                        hint="Check the provider's status and your network, then try again.",
                    ) from None
                delay = backoff_delay(failures, retry_after=error.retry_after, rng=self._rng)
                log.info("retrying %s in %.1f s (%s)", self.provider.name, delay, error.message)
                self._clock.sleep(delay)
                continue
            except ProviderError as exc:
                raise self._redacted_error(exc) from None
            self._charge(request, response, meter)
            return response

    # ------------------------------------------------------------ budget and usage

    def _check_budget(self, request: ProviderRequest, meter: _Meter) -> None:
        needed = estimate_tokens(request.system + request.user) + request.max_output_tokens
        left = meter.limit - meter.spent
        if needed > left:
            raise BudgetExceeded(
                f"the token budget is exhausted: the next {request.role.value} call may need "
                f"{needed} tokens and {max(left, 0)} are left",
                hint="Raise budget.run_tokens in your user config, or shorten the input.",
            )

    def _charge(self, request: ProviderRequest, response: ProviderResponse, meter: _Meter) -> None:
        cost = usd_cost(
            request.model,
            input_tokens=response.input_tokens,
            output_tokens=response.output_tokens,
            pricing=self._pricing,
        )
        meter.input_tokens += response.input_tokens
        meter.output_tokens += response.output_tokens
        if cost is not None:
            meter.cost_usd = round((meter.cost_usd or 0.0) + cost, 6)
        self.ledger.record(
            request.role.value,
            request.model,
            input_tokens=response.input_tokens,
            output_tokens=response.output_tokens,
            cost_usd=cost,
        )
        if meter.spent > meter.limit:
            raise BudgetExceeded(
                f"the token budget is exceeded: {meter.spent} tokens used of {meter.limit}",
                hint="Raise budget.run_tokens in your user config.",
            )


# ---------------------------------------------------------------- building a gateway


def _is_loopback(base_url: str | None) -> bool:
    if base_url is None:
        return False
    host = urlsplit(base_url).hostname
    return host is not None and host.lower() in _LOOPBACK


def api_key(llm: LlmConfig, environ: Mapping[str, str]) -> str:
    """Read the key from the variable named in `llm.api_key_env` (a user-only key)."""
    name = llm.api_key_env
    if llm.provider is ProviderName.OPENAI_COMPATIBLE and name.startswith("ANTHROPIC_"):
        raise UsageError(
            f"the openai-compatible provider will not send {name} to another server",
            hint="Set llm.api_key_env in your user config to the variable that holds this "
            "provider's key.",
        )
    value = environ.get(name, "")
    if value:
        return value
    if llm.provider is ProviderName.OPENAI_COMPATIBLE and _is_loopback(llm.base_url):
        return NO_KEY_PLACEHOLDER
    raise UsageError(
        f"{name} is not set",
        hint=f"Export {name} with your API key, or set llm.api_key_env in your user config.",
    )


def make_provider(llm: LlmConfig, *, environ: Mapping[str, str] | None = None) -> Provider:
    """The provider named by `llm.provider`. The SDK itself is imported on first use."""
    env = os.environ if environ is None else environ
    key = api_key(llm, env)
    if llm.provider is ProviderName.ANTHROPIC:
        return AnthropicProvider(api_key=key, base_url=llm.base_url)
    return OpenAICompatProvider(api_key=key, base_url=llm.base_url)


def open_gateway(
    llm: LlmConfig, *, redactor: Redactor, ledger: UsageLedger | None = None
) -> Gateway:
    """A gateway for the configured provider. Pass the redactor built from the full environment."""
    return Gateway(llm=llm, provider=make_provider(llm), redactor=redactor, ledger=ledger)
