"""`aipm scan` and `aipm task` (build prompt 06; ARCHITECTURE §16).

`scan` runs every scanner over a staged copy of the repository (the stub scanners here), exits 3
on a finding at `--fail-on` or above, 8 when the scanner named with `--scanner` is missing, and
needs trust only for config-defined scanners. `task` changes progress fields only, under the
lock, and records every change.
"""

import json
import os
import shutil
import sys
from collections.abc import Callable
from pathlib import Path

import pytest

from aipm.domain.models import ApprovalsDoc, ArtifactKind, Blocked, BlockedReason, TaskStatus
from aipm.llm.fake import FakeLLM
from aipm.state.attempts import load_snapshot
from aipm.state.store import open_store
from tests.conftest import REPO_ROOT
from tests.integration.conftest import UserDirs
from tests.integration.flow import aipm, load, ok, planned, tasks, trust
from tests.integration.test_verify_cli import edit_config

STUBS = REPO_ROOT / "tests" / "fakes" / "bin"


@pytest.fixture
def stubs(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("PATH", f"{STUBS}{os.pathsep}{os.environ['PATH']}")


@pytest.fixture
def repo(tmp_repo: Path, fake_llm: Callable[[str], FakeLLM], user_dirs: UserDirs) -> Path:
    fake_llm("clinic")
    planned(tmp_repo)
    return tmp_repo


# ---------------------------------------------------------------- scan


def test_scan_finds_a_planted_secret_and_fails(tmp_repo: Path, stubs: None) -> None:
    (tmp_repo / "app.py").write_text("TOKEN = 'FAKE-LEAK-FOR-TESTS'\n", encoding="utf-8")
    (tmp_repo / ".gitleaks.toml").write_text("[allowlist]\npaths = ['.*']\n", encoding="utf-8")
    result = aipm(tmp_repo, "scan", flags=["--json"])
    env = json.loads(result.stdout)
    assert result.exit_code == 3, env
    by_tool = {s["tool"]: s for s in env["data"]["scanners"]}
    assert [f["path"] for f in by_tool["gitleaks"]["findings"]] == ["app.py"]
    assert by_tool["trivy"]["findings"][0]["rule"] == "fake-token"
    assert env["data"]["failed"] is True


def test_scan_passes_a_clean_repository(tmp_repo: Path, stubs: None) -> None:
    result = aipm(tmp_repo, "scan")
    assert result.exit_code == 0, result.output
    assert "gitleaks: ok, 0 finding(s)" in result.stdout


def test_fail_on_critical_lets_a_high_finding_pass(tmp_repo: Path, stubs: None) -> None:
    (tmp_repo / "app.py").write_text("TOKEN = 'FAKE-LEAK-FOR-TESTS'\n", encoding="utf-8")
    result = aipm(tmp_repo, "scan", "--fail-on", "critical")
    assert result.exit_code == 0, result.output
    assert "high fake-token app.py:1" in result.stdout


def test_a_named_missing_scanner_exits_8(tmp_repo: Path, tmp_path: Path,
                                         monkeypatch: pytest.MonkeyPatch) -> None:  # fmt: skip
    empty = tmp_path / "bin"
    empty.mkdir()
    git = shutil.which("git")
    assert git is not None
    (empty / "git").symlink_to(git)
    monkeypatch.setenv("PATH", str(empty))
    result = aipm(tmp_repo, "scan", "--scanner", "semgrep")
    assert result.exit_code == 8, result.output
    assert "semgrep is not installed" in result.stderr


@pytest.mark.parametrize(("args", "message"), [
    (["--scanner", "nmap"], "no scanner 'nmap'"),
    (["--fail-on", "urgent"], "--fail-on is one of"),
])  # fmt: skip
def test_scan_usage_errors(tmp_repo: Path, args: list[str], message: str) -> None:
    result = aipm(tmp_repo, "scan", *args)
    assert result.exit_code == 2
    assert message in result.stderr


def test_config_defined_scanners_need_trust(repo: Path, stubs: None) -> None:
    script = repo / "check.py"
    script.write_text("import sys\nsys.exit(0)\n", encoding="utf-8")

    def add(layer: dict[str, object]) -> None:
        layer["scanners"] = {"extra": {"house": {"run": [sys.executable, "check.py"]}}}
        layer["allowed_executables"] = [*layer["allowed_executables"],  # type: ignore[misc]
                                        [sys.executable, "check.py"]]  # fmt: skip

    edit_config(repo, add)
    refused = aipm(repo, "scan", "--scanner", "house")
    assert refused.exit_code == 6, refused.output
    assert "aipm trust" in refused.stderr
    trust(repo)
    result = aipm(repo, "scan", "--scanner", "house")
    assert result.exit_code == 0, result.output
    script.write_text("import sys\nprint('bad thing')\nsys.exit(4)\n", encoding="utf-8")
    failed = aipm(repo, "scan", "--scanner", "house")
    assert failed.exit_code == 3
    assert "exit 4: bad thing" in failed.stdout


# ---------------------------------------------------------------- task


def task_of(repo: Path, task_id: str = "T-001"):
    return next(t for t in tasks(repo).tasks if t.id == task_id)


def test_show_reads_and_changes_nothing(repo: Path) -> None:
    before = (repo / ".pm" / "tasks.yaml").read_bytes()
    result = ok(aipm(repo, "task", "show", "T-002"))
    assert "T-002: Slots and appointments without double booking" in result.stdout
    assert "status: todo, attempts: 0" in result.stdout
    assert "AC-T002-1:" in result.stdout
    assert (repo / ".pm" / "tasks.yaml").read_bytes() == before
    data = json.loads(ok(aipm(repo, "task", "show", "T-002", flags=["--json"])).stdout)["data"]
    assert data["task"]["id"] == "T-002"


def test_block_unblock_skip_and_reset_are_recorded(repo: Path) -> None:
    ok(aipm(repo, "prompt", "T-001"))
    assert load_snapshot(repo, "T-001") is not None
    blocked = ok(aipm(repo, "task", "block", "T-001", "--reason", "waiting for the API key"))
    assert "T-001: in_progress -> blocked" in blocked.stdout
    task = task_of(repo)
    assert task.status is TaskStatus.BLOCKED
    assert task.blocked is not None and task.blocked.reason.value == "manual"
    ok(aipm(repo, "task", "unblock", "T-001"))
    assert task_of(repo).status is TaskStatus.IN_PROGRESS
    ok(aipm(repo, "task", "skip", "T-001", "--reason", "done by hand"))
    assert task_of(repo).status is TaskStatus.SKIPPED
    assert load_snapshot(repo, "T-001") is None
    ok(aipm(repo, "task", "reset", "T-001"))
    task = task_of(repo)
    assert (task.status, task.attempts, task.base_sha) == (TaskStatus.TODO, 0, None)
    changes = load(repo, ArtifactKind.APPROVALS, ApprovalsDoc).task_changes
    assert [(c.action.value, c.from_status.value, c.to_status.value) for c in changes] == [
        ("block", "in_progress", "blocked"),
        ("unblock", "blocked", "in_progress"),
        ("skip", "in_progress", "skipped"),
        ("reset", "skipped", "todo"),
    ]
    kinds = [json.loads(line)["kind"] for line in
             (repo / ".pm" / "events.jsonl").read_text(encoding="utf-8").splitlines()]  # fmt: skip
    assert kinds.count("task_change") == 1  # the skip


def test_unblocking_a_policy_block_is_a_security_event(repo: Path) -> None:
    ok(aipm(repo, "prompt", "T-001"))
    doc = tasks(repo)
    blocked = doc.model_copy(update={"tasks": [
        t.model_copy(update={"status": TaskStatus.BLOCKED, "blocked": Blocked(
            reason=BlockedReason.POLICY_VIOLATION, detail="protected_path")})
        if t.id == "T-001" else t for t in doc.tasks]})  # fmt: skip
    open_store(repo).save(blocked)
    ok(aipm(repo, "task", "unblock", "T-001", "--reason", "reviewed, it was me"))
    events = [json.loads(line) for line in
              (repo / ".pm" / "events.jsonl").read_text(encoding="utf-8").splitlines()]  # fmt: skip
    assert any(e["kind"] == "task_change" and "unblocked after a policy violation" in e["detail"]
               for e in events)  # fmt: skip


@pytest.mark.parametrize(("args", "message"), [
    (["block", "T-001"], "needs --reason"),
    (["unblock", "T-001"], "cannot unblock T-001: it is todo"),
    (["reset", "T-001"], "cannot reset T-001: it is todo"),
    (["show", "T-001", "--reason", "x"], "takes no --reason"),
    (["show", "T-099"], "no task T-099"),
    (["show", "T-1"], "not a task ID"),
])  # fmt: skip
def test_task_usage_errors(repo: Path, args: list[str], message: str) -> None:
    result = aipm(repo, "task", *args)
    assert result.exit_code == 2, result.output
    assert message in result.stderr


def test_task_changes_keep_the_plan_approved(repo: Path) -> None:
    ok(aipm(repo, "task", "skip", "T-001", "--reason", "not needed"))
    ok(aipm(repo, "prompt", "T-002"))
    assert task_of(repo, "T-002").status is TaskStatus.IN_PROGRESS
