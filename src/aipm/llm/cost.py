"""Token accounting; USD only when `llm.pricing` defines the model (ARCHITECTURE §14).

aipm ships no prices, so they cannot go stale: without a user-configured price, cost is None.
"""

from collections.abc import Mapping
from dataclasses import dataclass


def usd_cost(
    model: str, *, input_tokens: int, output_tokens: int, pricing: Mapping[str, Mapping[str, float]]
) -> float | None:
    """Return the USD cost, or None when the model has no configured price."""
    price = pricing.get(model)
    if price is None:
        return None
    total = input_tokens * price["input_per_mtok"] + output_tokens * price["output_per_mtok"]
    return round(total / 1_000_000, 6)


@dataclass(slots=True)
class UsageEntry:
    """Usage of one model by one role."""

    role: str
    model: str
    calls: int = 0
    input_tokens: int = 0
    output_tokens: int = 0
    cost_usd: float | None = None


class UsageLedger:
    """Tokens and cost per role and model for one command run."""

    def __init__(self) -> None:
        self._entries: dict[tuple[str, str], UsageEntry] = {}

    def record(
        self,
        role: str,
        model: str,
        *,
        input_tokens: int,
        output_tokens: int,
        cost_usd: float | None,
    ) -> None:
        """Add one provider call."""
        entry = self._entries.setdefault((role, model), UsageEntry(role=role, model=model))
        entry.calls += 1
        entry.input_tokens += input_tokens
        entry.output_tokens += output_tokens
        if cost_usd is not None:
            entry.cost_usd = round((entry.cost_usd or 0.0) + cost_usd, 6)

    @property
    def total_tokens(self) -> int:
        """Input plus output tokens of every call."""
        return sum(e.input_tokens + e.output_tokens for e in self._entries.values())

    @property
    def total_usd(self) -> float | None:
        """The summed cost of the priced calls, or None when no call had a price."""
        priced = [e.cost_usd for e in self._entries.values() if e.cost_usd is not None]
        return round(sum(priced), 6) if priced else None

    def to_data(self) -> dict[str, object]:
        """The `--json` payload."""
        return {
            "total_tokens": self.total_tokens,
            "total_usd": self.total_usd,
            "by_role": [
                {
                    "role": e.role,
                    "model": e.model,
                    "calls": e.calls,
                    "input_tokens": e.input_tokens,
                    "output_tokens": e.output_tokens,
                    "cost_usd": e.cost_usd,
                }
                for e in sorted(self._entries.values(), key=lambda e: (e.role, e.model))
            ],
        }
