"""`aipm build` and `aipm run` on the clinic example with the stub agent (build prompt 07,
ARCHITECTURE §12).

The clinic flow runs with FakeLLM to an approved, trusted plan; the gate menu uses this test
environment's ruff, compileall and pytest; the stub `claude`, scanners and `srt` go first on
PATH. T-001 is skipped, so T-002 is ready; the stub agent writes what each scenario says.
"""

import json
import os
from collections.abc import Callable
from pathlib import Path
from typing import Any

import pytest

from aipm.domain.models import JournalEventType, TaskStatus
from aipm.llm.fake import FakeLLM
from aipm.state.store import open_store
from tests.conftest import FakeSecrets, run_git
from tests.integration.build_flow import (
    agent_stderr,
    calls,
    copy_t002,
    fake_registry,
    journal,
    prepare_project,
    scenario,
    status,
)
from tests.integration.conftest import UserDirs
from tests.integration.flow import aipm, ok, tasks, trust
from tests.integration.test_verify_cli import STUBS, edit_config

pytestmark = pytest.mark.usefixtures("allow_unix_sockets")  # the asyncio loop self-pipe


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
    del fake_secrets  # every fake secret is in the environment; the stub checks none leaks
    fake_llm("clinic")
    return prepare_project(tmp_repo, monkeypatch, user_dirs.home)


def build(repo: Path, *args: str) -> tuple[int, dict[str, Any]]:
    result = aipm(repo, "build", *args, flags=["--json"])
    envelope: dict[str, Any] = json.loads(result.stdout)
    return result.exit_code, envelope


def test_a_good_agent_builds_the_task_and_it_lands_on_the_integration_branch(
    project: Path, user_dirs: UserDirs
) -> None:
    scenario(user_dirs.home, {"T-002": [{"steps": copy_t002(), "cost": 0.25}]})
    code, envelope = build(project, "--only", "T-002")
    assert code == 0, envelope
    data = envelope["data"]
    (outcome,) = data["tasks"]
    assert (outcome["task"], outcome["status"]) == ("T-002", "done")
    assert status(project, "T-002") is TaskStatus.DONE
    assert data["spent_usd"] == pytest.approx(0.25)
    commit = outcome["commit"]
    log = run_git(project, "log", "-1", "--format=%H%n%B", "aipm/integration")
    assert log.startswith(commit)
    assert "Aipm-Task: T-002" in log
    assert f"Aipm-Run: {data['run_id']}" in log
    assert "Aipm-Attempt: 1" in log
    # The user's branch is untouched; aipm merge is how it moves.
    assert run_git(project, "log", "-1", "--format=%s", "main").strip() == "base"
    assert "STUB-ASSERTION-FAILED" not in agent_stderr(project)
    (call,) = calls(user_dirs.home)
    assert call["resume"] is None
    kinds = [e.type for e in journal(project, data["run_id"])]
    assert kinds[0] is JournalEventType.RUN_STARTED
    assert JournalEventType.TASK_MERGED in kinds
    assert kinds[-1] is JournalEventType.RUN_FINISHED
    done = next(t for t in tasks(project).tasks if t.id == "T-002").done
    assert done is not None and done.commit == commit


def failing_t002() -> list[dict[str, Any]]:
    """The good implementation with a test that fails."""
    steps = copy_t002()
    steps.append({"append": "tests/booking/test_slots.py",
                  "text": '\n\ndef test_wrong() -> None:\n    assert len("x") == 2\n'})  # fmt: skip
    return steps


def test_a_failing_attempt_is_fixed_with_feedback_and_the_same_session(
    project: Path, user_dirs: UserDirs
) -> None:
    scenario(user_dirs.home, {"T-002": [
        {"steps": failing_t002(), "cost": 0.1},
        {"steps": copy_t002(), "cost": 0.2},
    ]})  # fmt: skip
    code, envelope = build(project, "--only", "T-002")
    assert code == 0, envelope
    first, second = calls(user_dirs.home)
    assert first["resume"] is None
    assert second["resume"] is not None  # the fix attempt resumes the agent's session
    data = envelope["data"]
    assert data["tasks"][0]["attempts"] == 2
    assert data["spent_usd"] == pytest.approx(0.3)  # 0.1, then the session's 0.3 minus 0.1
    fix = (project / ".pm" / "runs" / data["run_id"] / "prompts" / "T-002.2.md").read_text()
    assert "test_wrong" in fix  # the failing gate's output went back as feedback
    log = run_git(project, "log", "-1", "--format=%B", "aipm/integration")
    assert "Aipm-Attempt: 2" in log


def test_when_retries_run_out_the_task_is_blocked(project: Path, user_dirs: UserDirs) -> None:
    scenario(user_dirs.home, {"T-002": [{"steps": failing_t002()}]})
    code, envelope = build(project, "--only", "T-002", "--max-retries", "2")
    assert code == 3, envelope
    assert len(calls(user_dirs.home)) == 2
    (outcome,) = envelope["data"]["tasks"]
    assert (outcome["status"], outcome["reason"]) == ("blocked", "gates_failed")
    assert "unit" in outcome["detail"]
    blocked = next(t for t in tasks(project).tasks if t.id == "T-002").blocked
    assert blocked is not None and blocked.reason.value == "gates_failed"
    assert run_git(project, "rev-parse", "aipm/integration") == run_git(
        project, "rev-parse", "main"
    )


def test_aipm_blocked_only_blocks_the_task(project: Path, user_dirs: UserDirs) -> None:
    question = "AIPM-BLOCKED: Which \x1b[31mSMS\x1b[0m provider should I use?"
    scenario(user_dirs.home, {"T-002": [{"steps": copy_t002(), "text": f"Stuck.\n{question}"}]})
    code, envelope = build(project, "--only", "T-002")
    assert code == 3, envelope
    assert len(calls(user_dirs.home)) == 1  # a question is never retried
    (outcome,) = envelope["data"]["tasks"]
    assert (outcome["reason"], outcome["question"]) == (
        "agent_blocked", "Which SMS provider should I use?",
    )  # fmt: skip
    shown = aipm(project, "build", "--only", "T-002")  # human output of the next run
    assert "\x1b" not in shown.stdout + shown.stderr


def test_the_agents_claims_carry_no_authority(project: Path, user_dirs: UserDirs) -> None:
    """Prints `AIPM-DONE` (SECURITY.md §14.3): ignored; the gates decide."""
    scenario(user_dirs.home, {"T-002": [{"steps": failing_t002(),
                                         "text": "All tests pass.\nAIPM-DONE"}]})  # fmt: skip
    code, envelope = build(project, "--only", "T-002", "--max-retries", "1")
    assert code == 3, envelope
    assert status(project, "T-002") is TaskStatus.BLOCKED


def test_dry_run_compiles_and_shows_but_dispatches_and_writes_nothing(
    project: Path, user_dirs: UserDirs
) -> None:
    scenario(user_dirs.home, {"T-002": [{"steps": copy_t002()}]})
    before = sorted(p.name for p in (project / ".pm").iterdir())
    code, envelope = build(project, "--dry-run")
    assert code == 0, envelope
    data = envelope["data"]
    assert data["dry_run"] is True
    assert data["batches"][0] == ["T-002"]
    first = data["tasks"][0]
    assert first["task"] == "T-002"
    argv = first["argv"]
    assert "--bare" in argv
    assert argv[argv.index("--permission-mode") + 1] == "dontAsk"
    assert calls(user_dirs.home) == []
    assert sorted(p.name for p in (project / ".pm").iterdir()) == before
    assert "aipm/integration" not in run_git(project, "branch", "--list", "aipm/*")
    human = aipm(project, "build", "--dry-run")
    ok(human)
    assert "nothing is dispatched" in human.stdout


def test_run_builds_one_task(project: Path, user_dirs: UserDirs) -> None:
    scenario(user_dirs.home, {"T-002": [{"steps": copy_t002()}]})
    result = aipm(project, "run", "T-002", flags=["--json"])
    assert result.exit_code == 0, result.stdout
    assert json.loads(result.stdout)["data"]["tasks"][0]["status"] == "done"


@pytest.mark.parametrize(
    ("task", "message"),
    [("T-003", "depends on T-002"), ("T-099", "no task T-099"), ("T-1", "not a task ID")],
)
def test_run_refuses_a_task_that_cannot_start(project: Path, task: str, message: str) -> None:
    result = aipm(project, "run", task, flags=["--json"])
    assert result.exit_code == 2, result.stdout
    assert message in json.loads(result.stdout)["errors"][0]["message"]


def test_a_task_in_progress_in_manual_mode_is_left_alone(
    project: Path, user_dirs: UserDirs
) -> None:
    ok(aipm(project, "prompt", "T-002"))
    scenario(user_dirs.home, {"T-002": [{"steps": copy_t002()}]})
    code, envelope = build(project)
    assert code == 2, envelope
    assert "verify T-002" in envelope["errors"][0]["hint"]
    assert calls(user_dirs.home) == []


# ---------------------------------------------------------------- preconditions (§12.1)


def test_an_untrusted_surface_exits_6(project: Path) -> None:
    edit_config(project, lambda layer: layer.update({"test_roots": ["tests", "more"]}))
    code, envelope = build(project)
    assert code == 6, envelope


def test_dispatch_turned_off_exits_2(project: Path) -> None:
    edit_config(project, lambda layer: layer.update({"dispatch": {"enabled": False}}))
    trust(project)
    code, envelope = build(project)
    assert code == 2, envelope
    assert "dispatch is turned off" in envelope["errors"][0]["message"]


def test_a_dirty_tree_exits_2(project: Path) -> None:
    (project / "notes.txt").write_text("wip\n", encoding="utf-8")
    code, envelope = build(project)
    assert code == 2, envelope
    assert "not clean: notes.txt" in envelope["errors"][0]["message"]


def test_a_claude_without_a_required_flag_exits_8(project: Path, user_dirs: UserDirs) -> None:
    scenario(user_dirs.home, {}, help_drop=["--strict-mcp-config"])
    code, envelope = build(project)
    assert code == 8, envelope
    assert "--strict-mcp-config" in envelope["errors"][0]["message"]


def test_no_api_key_exits_8(project: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("ANTHROPIC_API_KEY")
    code, envelope = build(project)
    assert code == 8, envelope
    assert "ANTHROPIC_API_KEY" in envelope["errors"][0]["message"]


def test_a_held_lock_exits_7(project: Path) -> None:
    with open_store(project).lock():
        code, envelope = build(project)
    assert code == 7, envelope


def test_a_required_sandbox_that_is_missing_exits_8(
    project: Path, user_dirs: UserDirs, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    (user_dirs.config).write_text("schema_version: 1\nsecurity: {require_sandbox: true}\n")
    trust(project)
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    for name in ("claude", "gitleaks", "semgrep", "osv-scanner", "trivy"):
        (bin_dir / name).symlink_to(STUBS / name)
    monkeypatch.setenv("PATH", f"{bin_dir}{os.pathsep}/usr/bin{os.pathsep}/bin")
    code, envelope = build(project)
    assert code == 8, envelope
    assert "sandbox is required" in envelope["errors"][0]["message"]


def test_a_repository_cannot_make_a_user_branch_the_integration_branch(project: Path) -> None:
    edit_config(project, lambda layer: layer.update({"git": {"integration_branch": "main"}}))
    code, envelope = build(project)
    assert code == 6, envelope
    assert "not one of aipm's own branches" in envelope["errors"][0]["message"]
    assert run_git(project, "log", "-1", "--format=%s", "main").strip() == "base"


def test_bad_flags_exit_2(project: Path) -> None:
    for args in (["--parallel", "9"], ["--timeout", "soon"], ["--budget", "-1"],
                 ["--only", "T-1,x"], ["--max-retries", "11"]):  # fmt: skip
        code, envelope = build(project, *args)
        assert code == 2, (args, envelope)
