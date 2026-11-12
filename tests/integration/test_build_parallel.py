"""Parallel batches and the run budget (ARCHITECTURE §12.3, §12.5; the v0.3 acceptance criteria).

- **Parallel:** 12 tasks with `--parallel 3` all finish; the journal's timestamps show at most
  three at a time, and the tasks that own the same serialized path never at the same time.
- **Budget:** the build stops dispatching once the next attempt would pass `run_usd`, lets the
  running attempts finish and exits 5.
"""

import json
from collections.abc import Callable
from datetime import datetime
from pathlib import Path
from typing import Any

import pytest

from aipm.domain.models import JournalEventType, RoleName, TaskStatus
from aipm.llm.fake import FakeLLM, FakeResponse
from tests.conftest import FakeSecrets
from tests.integration.build_flow import (
    calls,
    copy_t002,
    fake_registry,
    journal,
    package_steps,
    prepare_project,
    scenario,
    status,
    task_commits,
    without_ac_review,
)
from tests.integration.conftest import UserDirs
from tests.integration.flow import aipm, reply

pytestmark = pytest.mark.usefixtures("allow_unix_sockets")
SERIALIZED_PAIRS = (("T-003", "T-007"), ("T-005", "T-009"))


@pytest.fixture(autouse=True)
def registry(monkeypatch: pytest.MonkeyPatch) -> None:
    fake_registry(monkeypatch)


def twelve_tasks() -> dict[str, Any]:
    """The clinic plan reply, with 12 small tasks: T-003 and T-007 both own `uv.lock`, T-005 and
    T-009 both own a migration (serialized paths); T-012 depends on T-001."""
    base = reply("planner")
    traces = sorted({t for task in base["tasks"] for t in task["traces"]})
    tasks: list[dict[str, Any]] = []
    for n in range(1, 13):
        owns = [f"src/clinic/m{n:02d}/**", f"tests/m{n:02d}/**"]
        if n in (3, 7):
            owns.append("uv.lock")
        if n in (5, 9):
            owns.append("migrations/0001.sql")
        tasks.append({
            "id": f"T-{n:03d}", "title": f"Module {n}", "description": "A small module.",
            "type": "feature", "traces": traces if n == 1 else traces[:1],
            "depends_on": ["T-001"] if n == 12 else [], "owns_files": owns, "reads_files": [],
            "deps_add": [], "acceptance": [f"Module {n} returns one"],
            "gates": ["lint", "unit", "ac_trace"], "size": "S",
        })  # fmt: skip
    return {**base, "tasks": tasks}


@pytest.fixture
def twelve(
    tmp_repo: Path,
    fake_llm: Callable[[str], FakeLLM],
    fake_secrets: FakeSecrets,
    monkeypatch: pytest.MonkeyPatch,
    user_dirs: UserDirs,
) -> Path:
    del fake_secrets
    llm = fake_llm("clinic")
    llm._queues[RoleName.PLANNER] = [FakeResponse.model_validate({"json": twelve_tasks()})]  # pyright: ignore[reportPrivateUsage]
    repo = prepare_project(tmp_repo, monkeypatch, user_dirs.home)
    aipm(repo, "task", "reset", "T-001", "--reason", "the twelve-task plan builds it")
    without_ac_review(repo)
    plan = {
        f"T-{n:03d}": [{"steps": [{"sleep": 1}, *package_steps(
            repo, f"T-{n:03d}", f"m{n:02d}", f"tests/m{n:02d}/test_m{n:02d}.py")]}]
        for n in range(1, 13)
    }  # fmt: skip
    scenario(user_dirs.home, plan)
    return repo


def intervals(repo: Path, run_id: str) -> dict[str, tuple[datetime, datetime]]:
    """For each task, from its worktree to its merge."""
    start: dict[str, datetime] = {}
    spans: dict[str, tuple[datetime, datetime]] = {}
    for event in journal(repo, run_id):
        if event.task is None:
            continue
        if event.type is JournalEventType.WORKTREE_CREATED:
            start[event.task] = event.ts
        elif event.type in (JournalEventType.TASK_MERGED, JournalEventType.TASK_BLOCKED):
            spans[event.task] = (start[event.task], event.ts)
    return spans


def overlap(a: tuple[datetime, datetime], b: tuple[datetime, datetime]) -> bool:
    return a[0] < b[1] and b[0] < a[1]


def test_twelve_tasks_three_at_a_time(twelve: Path, user_dirs: UserDirs) -> None:
    result = aipm(twelve, "build", "--parallel", "3", flags=["--json"])
    assert result.exit_code == 0, result.stdout
    data = json.loads(result.stdout)["data"]
    assert sorted(t["task"] for t in data["tasks"] if t["status"] == "done") == [
        f"T-{n:03d}" for n in range(1, 13)
    ]
    assert sorted(task_commits(twelve)) == [f"T-{n:03d}" for n in range(1, 13)]
    spans = intervals(twelve, data["run_id"])
    assert len(spans) == 12
    moments = sorted({t for span in spans.values() for t in span})
    most = max(sum(1 for s in spans.values() if s[0] <= m < s[1]) for m in moments)
    assert 2 <= most <= 3, most
    for a, b in SERIALIZED_PAIRS:
        assert not overlap(spans[a], spans[b]), (a, b)
    assert not overlap(spans["T-001"], spans["T-012"])  # a dependency


def test_the_budget_stops_new_dispatches_and_lets_running_ones_finish(
    twelve: Path, user_dirs: UserDirs
) -> None:
    user_dirs.config.write_text("schema_version: 1\nbudget: {task_usd: 0.5}\n")
    plan = json.loads((user_dirs.home / ".stub-claude" / "scenario.json").read_text())
    for attempts in plan["tasks"].values():
        attempts[0]["cost"] = 0.3
    scenario(user_dirs.home, plan["tasks"])
    result = aipm(twelve, "build", "--parallel", "2", "--budget", "1.0", flags=["--json"])
    assert result.exit_code == 5, result.stdout
    data = json.loads(result.stdout)["data"]
    assert data["budget_exceeded"] is True
    # Two attempts fit (0.5 held each); after they cost 0.3 each, 0.6 + 0.5 > 1.0.
    assert len(calls(user_dirs.home)) == 2
    assert [t["status"] for t in data["tasks"]] == ["done", "done"]
    events = journal(twelve, data["run_id"])
    kinds = [e.type for e in events]
    stop = kinds.index(JournalEventType.BUDGET_EXCEEDED)
    assert JournalEventType.AGENT_STARTED not in kinds[stop:]
    assert status(twelve, "T-003") is TaskStatus.TODO
    assert data["spent_usd"] == pytest.approx(0.6)


def test_a_single_task_over_its_budget_is_charged_and_stopped(
    tmp_repo: Path,
    fake_llm: Callable[[str], FakeLLM],
    fake_secrets: FakeSecrets,
    monkeypatch: pytest.MonkeyPatch,
    user_dirs: UserDirs,
) -> None:
    """The agent stops at its task budget (`error_max_budget_usd`): a failed attempt."""
    del fake_secrets
    fake_llm("clinic")
    repo = prepare_project(tmp_repo, monkeypatch, user_dirs.home)
    over = {"steps": copy_t002(), "cost": 2.5, "error": True, "subtype": "error_max_budget_usd"}
    scenario(user_dirs.home, {"T-002": [over]})
    result = aipm(repo, "build", "--only", "T-002", "--max-retries", "1", flags=["--json"])
    assert result.exit_code == 3, result.stdout
    data = json.loads(result.stdout)["data"]
    assert data["spent_usd"] == pytest.approx(2.5)  # what it reported, over the cap
    report = (repo / ".pm/runs" / data["run_id"] / "gates/T-002/1/report.yaml").read_text()
    assert "error_max_budget_usd" in report
