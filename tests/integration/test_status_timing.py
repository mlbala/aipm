"""`aipm status` timing (build prompt 04, ARCHITECTURE §20). Skipped on CI unless asked for.

`tasks.yaml` holds at most 200 tasks (§6.3), so the 500-task budget applies to the in-memory
status path: phase derivation, the status view and its rendering. The full command, which also
parses `tasks.yaml` with the pure-Python YAML parser, is measured on a generated 200-task file
with a looser regression bound; its cost is dominated by YAML parsing (see the step 04 report).
"""

import time
from collections.abc import Callable
from pathlib import Path

import pytest

from aipm.app import status as use_case
from aipm.config.schema import BudgetConfig
from aipm.domain.models import (
    AcceptanceCriterion,
    StateSnapshot,
    Task,
    TasksDerivedFrom,
    TasksDoc,
    TaskSize,
    TaskType,
)
from aipm.domain.phase import derive_phase
from aipm.llm.fake import FakeLLM
from aipm.reporting.status import build_status, render_status
from aipm.reporting.worksheet import render_worksheet
from aipm.state.store import open_store
from tests.integration.flow import aipm, designed, ok, tasks

BUDGET_S = 0.300
FULL_COMMAND_BOUND_S = 2.0


def generated(count: int) -> list[Task]:
    return [
        Task(
            id=f"T-{n:03d}",
            title=f"Task number {n} with a realistic title",
            description="Build the part of the system this task owns. " * 10,
            type=TaskType.FEATURE,
            traces=["F-001"],
            depends_on=[f"T-{n - 1:03d}"] if n > 1 else [],
            owns_files=[f"src/m{n}/a.py", f"src/m{n}/b.py", f"tests/m{n}/test_a.py"],
            reads_files=["src/common/**"],
            acceptance=[
                AcceptanceCriterion(id=f"AC-T{n:03d}-{k}", text=f"Criterion {k} holds")
                for k in range(1, 5)
            ],
            gates=["lint", "unit", "ac_trace"],
            size=TaskSize.M,
        )
        for n in range(1, count + 1)
    ]


def best_of(runs: int, step: Callable[[], object]) -> float:
    best = float("inf")
    for _ in range(runs):
        start = time.perf_counter()
        step()
        best = min(best, time.perf_counter() - start)
    return best


@pytest.mark.timing
def test_the_status_view_of_500_tasks_takes_under_300_ms() -> None:
    derived = TasksDerivedFrom(prd="1" * 64, architecture="2" * 64, threat_model="3" * 64)
    # model_construct: 500 is over the tasks.yaml cap, which only applies to the file.
    doc = TasksDoc.model_construct(derived_from=derived, tasks=generated(500))
    snapshot = StateSnapshot(initialized=True, tasks=doc)

    def view() -> None:
        status = build_status(snapshot, derive_phase(snapshot), [], BudgetConfig())
        render_status(status, show_all=True)
        render_worksheet(doc)

    assert best_of(3, view) < BUDGET_S


@pytest.mark.timing
def test_the_full_command_on_a_generated_200_task_plan(
    tmp_repo: Path, fake_llm: Callable[[str], FakeLLM]
) -> None:
    fake_llm("clinic")
    designed(tmp_repo)
    ok(aipm(tmp_repo, "plan", flags=["--yes"]))
    open_store(tmp_repo).save(tasks(tmp_repo).model_copy(update={"tasks": generated(200)}))

    def run() -> None:
        use_case.run(tmp_repo, show_all=True, task_id=None, ack=None)

    elapsed = best_of(3, run)
    assert elapsed < FULL_COMMAND_BOUND_S, f"aipm status took {elapsed:.3f} s"
