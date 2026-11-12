"""Run and task budgets (ARCHITECTURE §12.5)."""

import math
import threading

import pytest

from aipm.domain.errors import BudgetExceeded, UsageError
from aipm.security.budget import RunBudget, Spend, TokenCounter, attempt_cost, check_budget


def test_the_task_budget_never_exceeds_the_run_budget() -> None:
    assert RunBudget.of(run_usd=1.0, task_usd=2.0, run_tokens=10).task_usd == 1.0
    assert RunBudget.of(run_usd=10.0, task_usd=2.0, run_tokens=10) == RunBudget(10.0, 2.0, 10)


@pytest.mark.parametrize(
    ("run", "task", "tokens"),
    [(0.0, 1.0, 1), (1.0, -1.0, 1), (math.inf, 1.0, 1), (math.nan, 1.0, 1), (1.0, 1.0, 0),
     (True, 1.0, 1), (1.0, 1.0, True)],
)  # fmt: skip
def test_limits_must_be_positive_amounts(run: float, task: float, tokens: int) -> None:
    with pytest.raises(UsageError):
        RunBudget.of(run_usd=run, task_usd=task, run_tokens=tokens)


def test_check_budget() -> None:
    check_budget(spent_usd=8.0, limit_usd=10.0, reserved_usd=0.0, next_usd=2.0)
    check_budget(spent_usd=0.1 + 0.2, limit_usd=0.3)  # float noise is not overspending
    with pytest.raises(BudgetExceeded) as caught:
        check_budget(spent_usd=8.0, limit_usd=10.0, reserved_usd=0.5, next_usd=2.0)
    assert caught.value.exit_code == 5


def test_running_attempts_hold_their_task_budget() -> None:
    spend = Spend(RunBudget.of(run_usd=5.0, task_usd=2.0, run_tokens=10))
    assert spend.may_dispatch()
    spend.reserve("T-001/1")
    spend.reserve("T-002/1")
    assert spend.reserved_usd == 4.0
    assert not spend.may_dispatch()  # 4 held + 2 more > 5
    with pytest.raises(BudgetExceeded):
        spend.reserve("T-003/1")
    spend.settle("T-001/1", 0.5)
    assert spend.may_dispatch()  # 0.5 spent + 2 held + 2 more <= 5
    spend.settle("T-002/1", -3.0)  # a negative report never refunds
    assert (spend.spent_usd, spend.reserved_usd) == (0.5, 0.0)


def test_an_attempt_costs_the_session_increase_or_its_cap() -> None:
    assert attempt_cost(reported_total=0.75, previous_total=0.0, cap=2.0) == 0.75
    assert attempt_cost(reported_total=1.25, previous_total=0.75, cap=2.0) == 0.5  # --resume
    assert attempt_cost(reported_total=0.5, previous_total=0.75, cap=2.0) == 0.0
    for missing in (None, math.nan, math.inf, -1.0):
        assert attempt_cost(reported_total=missing, previous_total=0.0, cap=2.0) == 2.0


def test_the_token_counter_is_shared_across_threads() -> None:
    counter = TokenCounter(10_000)
    threads = [
        threading.Thread(target=lambda: [counter.add(1) for _ in range(1000)]) for _ in range(8)
    ]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()
    assert counter.used == 8000
    assert counter.remaining() == 2000
    counter.add(-50)
    counter.add(2000)
    with pytest.raises(BudgetExceeded, match="10000 tokens"):
        counter.remaining()
