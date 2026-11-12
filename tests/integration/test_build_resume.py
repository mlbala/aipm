"""Crash, interrupt and resume (ARCHITECTURE §12.6; the v0.3 acceptance criteria).

aipm runs as a real process here, so it can be killed. The gate menu leaves out the optional AC
reviewer (no FakeLLM in another process); the tasks are T-002, T-005, T-006 and T-007 of the
clinic plan, which build one after another.
"""

import json
import os
import signal
import threading
import time
from collections.abc import Callable
from pathlib import Path

import pytest

from aipm.domain.models import JournalEventType, TaskStatus
from aipm.execution.process import ProcessResult, running_groups
from aipm.llm.fake import FakeLLM
from tests.conftest import FakeSecrets
from tests.integration.build_flow import (
    calls,
    copy_t002,
    fake_registry,
    journal,
    package_steps,
    prepare_project,
    run_aipm_process,
    scenario,
    status,
    task_commits,
    without_ac_review,
)
from tests.integration.conftest import UserDirs
from tests.integration.flow import aipm

pytestmark = pytest.mark.usefixtures("allow_unix_sockets")
FOUR = "T-002,T-005,T-006,T-007"


@pytest.fixture(autouse=True)
def registry(monkeypatch: pytest.MonkeyPatch) -> None:
    fake_registry(monkeypatch)


@pytest.fixture
def project(
    tmp_repo: Path,
    fake_llm: Callable[[str], FakeLLM],
    fake_secrets: FakeSecrets,
    monkeypatch: pytest.MonkeyPatch,
    user_dirs: UserDirs,
) -> Path:
    del fake_secrets
    fake_llm("clinic")
    repo = prepare_project(tmp_repo, monkeypatch, user_dirs.home)
    without_ac_review(repo)
    return repo


def wait_for(path: Path, timeout: float = 120.0) -> None:
    deadline = time.monotonic() + timeout
    while not path.exists():
        assert time.monotonic() < deadline, f"{path.name} never appeared"
        time.sleep(0.05)


def in_background(repo: Path, *args: str) -> tuple[threading.Thread, list[ProcessResult]]:
    results: list[ProcessResult] = []
    thread = threading.Thread(
        target=lambda: results.append(run_aipm_process(repo, *args)), daemon=True
    )
    thread.start()
    return thread, results


def four_tasks(repo: Path, home: Path, *, blocking_t005: bool) -> None:
    def files(task: str, package: str, test: str, *, blocking: bool = False) -> list[object]:
        return package_steps(repo, task, package, test, blocking=blocking)

    scenario(home, {
        "T-002": [{"steps": copy_t002()}],
        "T-005": [
            {"steps": files("T-005", "notify", "tests/notify/test_notify.py",
                            blocking=blocking_t005)},
            {"steps": files("T-005", "notify", "tests/notify/test_notify.py")},
        ],
        "T-006": [{"steps": files("T-006", "staff", "tests/staff/test_staff.py")}],
        "T-007": [{"steps": [{"write": "src/clinic/staff/report.py",
                              "text": '"""T-007."""\n\n\ndef total() -> int:\n'
                                      '    """Return one."""\n    return 1\n'},
                             {"write": "tests/staff/test_report.py",
                              "text": _report_test(repo)}]}],
    })  # fmt: skip


def _report_test(repo: Path) -> str:
    from tests.integration.flow import tasks  # noqa: PLC0415

    ids = " ".join(c.id for c in next(t for t in tasks(repo).tasks if t.id == "T-007").acceptance)
    return (
        '"""T-007 tests."""\n\nfrom clinic.staff.report import total\n\n\n'
        f'def test_total() -> None:\n    """{ids}: the total is one."""\n    assert total() == 1\n'
    )


def test_a_build_killed_during_the_gates_resumes_with_one_commit_per_task(
    project: Path, user_dirs: UserDirs
) -> None:
    stub = user_dirs.home / ".stub-claude"
    four_tasks(project, user_dirs.home, blocking_t005=True)
    (stub / "hold").write_text("hold", encoding="utf-8")
    thread, _ = in_background(project, "build", "--only", FOUR)
    wait_for(stub / "in-gates")  # T-005, task 2 of 4, is running its unit gate
    (pid,) = running_groups()
    os.kill(pid, signal.SIGKILL)
    thread.join(timeout=60)
    (stub / "hold").unlink()
    wait_for(stub / "gates-done", timeout=30)  # the orphaned gate has finished
    assert status(project, "T-002") is TaskStatus.DONE
    assert status(project, "T-005") is TaskStatus.IN_PROGRESS

    result = aipm(project, "build", "--only", FOUR, flags=["--json"])
    assert result.exit_code == 0, result.stdout
    data = json.loads(result.stdout)["data"]
    assert data["resumed"] is True
    for task in FOUR.split(","):
        assert status(project, task) is TaskStatus.DONE, task
    commits = task_commits(project)
    assert sorted(commits) == sorted(FOUR.split(",")), commits  # exactly one each
    assert [c["task"] for c in calls(user_dirs.home)].count("T-005") == 2
    kinds = [e.type for e in journal(project, data["run_id"])]
    assert kinds.count(JournalEventType.RUN_STARTED) == 1  # the same run, resumed
    assert kinds[-1] is JournalEventType.RUN_FINISHED


def test_a_second_ctrl_c_kills_at_once_and_the_run_resumes(
    project: Path, user_dirs: UserDirs
) -> None:
    scenario(user_dirs.home, {"T-002": [{"steps": [{"sleep": 120}]}, {"steps": copy_t002()}]})
    thread, results = in_background(project, "build", "--only", "T-002")
    deadline = time.monotonic() + 60
    while not calls(user_dirs.home):
        assert time.monotonic() < deadline, "the agent never started"
        time.sleep(0.05)
    (pid,) = running_groups()
    started = time.monotonic()
    os.kill(pid, signal.SIGINT)
    time.sleep(0.5)
    os.kill(pid, signal.SIGINT)
    thread.join(timeout=60)
    assert time.monotonic() - started < 20
    (result,) = results
    assert result.returncode == 130, result.stdout[-2000:]
    envelope = json.loads(result.stdout)
    assert envelope["errors"][0]["code"] == "INTERRUPTED"
    run_id = envelope["data"]["run_id"]
    kinds = [e.type for e in journal(project, run_id)]
    assert JournalEventType.INTERRUPTED in kinds
    assert JournalEventType.RUN_FINISHED not in kinds
    assert status(project, "T-002") is TaskStatus.IN_PROGRESS

    resumed = aipm(project, "build", "--only", "T-002", flags=["--json"])
    assert resumed.exit_code == 0, resumed.stdout
    data = json.loads(resumed.stdout)["data"]
    assert (data["run_id"], data["resumed"]) == (run_id, True)
    assert status(project, "T-002") is TaskStatus.DONE


def test_a_first_ctrl_c_lets_running_work_finish_and_starts_nothing_new(
    project: Path, user_dirs: UserDirs
) -> None:
    four_tasks(project, user_dirs.home, blocking_t005=False)
    plan = json.loads((user_dirs.home / ".stub-claude" / "scenario.json").read_text())
    plan["tasks"]["T-002"][0]["steps"].insert(0, {"sleep": 3})
    scenario(user_dirs.home, plan["tasks"])
    thread, results = in_background(project, "build", "--only", FOUR)
    deadline = time.monotonic() + 60
    while not calls(user_dirs.home):
        assert time.monotonic() < deadline, "the agent never started"
        time.sleep(0.05)
    (pid,) = running_groups()
    os.kill(pid, signal.SIGINT)
    thread.join(timeout=120)
    (result,) = results
    assert result.returncode == 130, result.stdout[-2000:]
    assert status(project, "T-002") is TaskStatus.DONE  # finished within the grace period
    assert status(project, "T-005") is TaskStatus.TODO  # never started
    assert [c["task"] for c in calls(user_dirs.home)] == ["T-002"]


def test_sigterm_stops_a_build_like_ctrl_c(project: Path, user_dirs: UserDirs) -> None:
    """A supervisor's SIGTERM (or a closed terminal's SIGHUP) must not orphan the agent."""
    scenario(user_dirs.home, {"T-002": [{"steps": [{"sleep": 3}, *copy_t002()]}]})
    thread, results = in_background(project, "build", "--only", FOUR)
    deadline = time.monotonic() + 60
    while not calls(user_dirs.home):
        assert time.monotonic() < deadline, "the agent never started"
        time.sleep(0.05)
    (pid,) = running_groups()
    os.kill(pid, signal.SIGTERM)
    thread.join(timeout=120)
    (result,) = results
    assert result.returncode == 130, result.stdout[-2000:]
    assert status(project, "T-002") is TaskStatus.DONE
    assert status(project, "T-005") is TaskStatus.TODO
