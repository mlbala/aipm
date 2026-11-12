"""Run and task budgets in USD and tokens (C-20, ARCHITECTURE §12.5). Pure.

- **Run USD.** Checked before each dispatch: the spend so far, plus `task_usd` for every
  attempt still running, plus `task_usd` for the next one, may not pass `run_usd`. When it
  would, the build stops scheduling, lets the running attempts finish and exits 5. A task holds
  its `task_usd` from the moment it is scheduled, so a parallel batch never starts more tasks
  than the budget can dispatch (red-team v0.3).
- **Task USD.** Passed to the agent (`--max-budget-usd`); an attempt whose cost is unknown is
  charged in full.
- **Tokens.** `run_tokens` bounds aipm's own LLM roles (the AC reviewer) for the whole run;
  reviews run in gate threads, so the counter takes a lock.
"""

import math
import threading
from dataclasses import dataclass, field

from aipm.domain.errors import BudgetExceeded, UsageError

_SLACK = 1e-9


def _amount(value: float, what: str) -> float:
    if isinstance(value, bool) or not math.isfinite(value) or value <= 0:
        raise UsageError(f"{what} must be a positive amount, not {value!r}")
    return float(value)


@dataclass(frozen=True, slots=True)
class RunBudget:
    """The limits of one run. `task_usd` never exceeds `run_usd`."""

    run_usd: float
    task_usd: float
    run_tokens: int

    @classmethod
    def of(cls, *, run_usd: float, task_usd: float, run_tokens: int) -> "RunBudget":
        """A checked budget (exit 2 for a limit that is not a positive amount)."""
        run = _amount(run_usd, "budget.run_usd")
        task = min(_amount(task_usd, "budget.task_usd"), run)
        if isinstance(run_tokens, bool) or run_tokens <= 0:
            raise UsageError(f"budget.run_tokens must be positive, not {run_tokens!r}")
        return cls(run, task, int(run_tokens))


def check_budget(
    *, spent_usd: float, limit_usd: float, reserved_usd: float = 0.0, next_usd: float = 0.0
) -> None:
    """Raise `BudgetExceeded` (exit 5) when `spent + reserved + next` would pass the limit."""
    if spent_usd + reserved_usd + next_usd > limit_usd + _SLACK:
        raise BudgetExceeded(
            f"the run budget of ${limit_usd:.2f} would be exceeded: ${spent_usd:.2f} spent, "
            f"${reserved_usd:.2f} held for running attempts, ${next_usd:.2f} for the next",
            hint="Raise budget.run_usd in your user config, or pass --budget, then run "
            "`aipm build` again; finished tasks are kept.",
        )


@dataclass(slots=True)
class Spend:
    """What a run has spent, and what its running attempts may still spend."""

    budget: RunBudget
    spent_usd: float = 0.0
    reserved: dict[str, float] = field(default_factory=dict[str, float])

    @property
    def reserved_usd(self) -> float:
        """`task_usd` for each attempt still running."""
        return sum(self.reserved.values())

    def may_dispatch(self, *, held: str | None = None) -> bool:
        """Whether one more attempt fits in the run budget; `held` names a hold that attempt
        would use (its task's, taken when the task was scheduled)."""
        reserved = self.reserved_usd - (self.reserved.get(held, 0.0) if held else 0.0)
        total = self.spent_usd + reserved + self.budget.task_usd
        return total <= self.budget.run_usd + _SLACK

    def reserve(self, key: str, *, held: str | None = None) -> None:
        """Hold `task_usd` for the attempt `key`, in place of the hold `held` when given; exit
        5 when it does not fit."""
        if held is not None:
            self.reserved.pop(held, None)
        check_budget(
            spent_usd=self.spent_usd,
            limit_usd=self.budget.run_usd,
            reserved_usd=self.reserved_usd,
            next_usd=self.budget.task_usd,
        )
        self.reserved[key] = self.budget.task_usd

    def release(self, key: str) -> None:
        """Drop the hold `key`, unspent (a scheduled task that never dispatched)."""
        self.reserved.pop(key, None)

    def settle(self, key: str, cost_usd: float) -> None:
        """Release the hold of `key` and add what the attempt cost."""
        self.reserved.pop(key, None)
        self.spent_usd += max(cost_usd, 0.0)


def attempt_cost(*, reported_total: float | None, previous_total: float, cap: float) -> float:
    """What one attempt cost.

    Claude Code reports the whole session's total after `--resume`, so the session's total
    after the previous attempt is subtracted. With no valid report (killed, crashed) the
    attempt is charged `cap`, its task budget: spend is over-counted rather than missed.
    """
    if reported_total is None or not math.isfinite(reported_total) or reported_total < 0:
        return cap
    return max(reported_total - previous_total, 0.0)


class TokenCounter:
    """The tokens aipm's own LLM roles may still use in this run (`budget.run_tokens`)."""

    def __init__(self, limit: int) -> None:
        self.limit = limit
        self._used = 0
        self._lock = threading.Lock()

    @property
    def used(self) -> int:
        """Tokens used so far."""
        with self._lock:
            return self._used

    def remaining(self) -> int:
        """Tokens left; exit 5 when none are."""
        with self._lock:
            left = self.limit - self._used
        if left <= 0:
            raise BudgetExceeded(
                f"aipm's own LLM roles have used the run's {self.limit} tokens",
                hint="Raise budget.run_tokens in your user config.",
            )
        return left

    def add(self, tokens: int) -> None:
        """Count tokens a role call used."""
        with self._lock:
            self._used += max(tokens, 0)
