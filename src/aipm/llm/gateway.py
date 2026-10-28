"""The LLM gateway (C-5, ARCHITECTURE §14).

It never sends `temperature`, `top_p` or `top_k`, redacts every rendered prompt, validates
every response into the role's schema, and enforces the token budget.
"""

from dataclasses import dataclass
from typing import Protocol

from pydantic import BaseModel

from aipm.domain.models import RoleName


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
