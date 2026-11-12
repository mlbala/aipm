"""`aipm merge` and the spend in `aipm status` after a build (ARCHITECTURE §12.2, §17;
SECURITY.md §11).

The user's branch moves only by fast-forward, after the log is shown and a person confirms;
aipm never pushes, and never touches a branch checked out elsewhere or one of its own.
"""

import json
from collections.abc import Callable
from pathlib import Path
from typing import Any

import pytest

from aipm.app import merge as merge_app
from aipm.domain.errors import UsageError
from aipm.llm.fake import FakeLLM
from tests.conftest import FakeSecrets, run_git
from tests.integration.build_flow import copy_t002, fake_registry, prepare_project, scenario
from tests.integration.conftest import UserDirs
from tests.integration.flow import aipm, ok

pytestmark = pytest.mark.usefixtures("allow_unix_sockets")


@pytest.fixture(autouse=True)
def registry(monkeypatch: pytest.MonkeyPatch) -> None:
    fake_registry(monkeypatch)


@pytest.fixture
def built(
    tmp_repo: Path,
    fake_llm: Callable[[str], FakeLLM],
    fake_secrets: FakeSecrets,
    monkeypatch: pytest.MonkeyPatch,
    user_dirs: UserDirs,
    tmp_path: Path,
) -> Path:
    """The clinic project with T-002 built onto aipm/integration, and a bare `origin`."""
    del fake_secrets
    fake_llm("clinic")
    repo = prepare_project(tmp_repo, monkeypatch, user_dirs.home)
    remote = tmp_path / "origin.git"
    run_git(tmp_path, "init", "-q", "--bare", str(remote))
    run_git(repo, "remote", "add", "origin", str(remote))
    scenario(user_dirs.home, {"T-002": [{"steps": copy_t002(), "cost": 0.25}]})
    result = aipm(repo, "build", "--only", "T-002", flags=["--json"])
    assert result.exit_code == 0, result.stdout
    return repo


def interactive(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr("aipm.cli.output.stdin_is_terminal", lambda: True)


def head(repo: Path, ref: str) -> str:
    return run_git(repo, "rev-parse", ref).strip()


def envelope(repo: Path, *args: str) -> tuple[int, dict[str, Any]]:
    result = aipm(repo, "merge", *args, flags=["--json"])
    return result.exit_code, json.loads(result.stdout)


def test_merge_shows_the_log_and_needs_a_person(built: Path) -> None:
    before = head(built, "main")
    code, env = envelope(built)
    assert code == 4, env
    data = env["data"]
    assert data["into"] == "main"
    assert len(data["commits"]) == 1
    assert "aipm: T-002" in data["commits"][0]
    assert head(built, "main") == before


def test_a_confirmed_merge_fast_forwards_the_checked_out_branch(
    built: Path, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    interactive(monkeypatch)
    result = aipm(built, "merge", input="y\n")
    assert result.exit_code == 0, result.output
    assert "aipm: T-002" in result.stdout
    assert head(built, "main") == head(built, "aipm/integration")
    assert (built / "src" / "clinic" / "booking" / "service.py").exists()
    assert run_git(built, "status", "--porcelain", "--", ".", ":!.pm") == ""
    # Never a push: the remote has no refs at all.
    assert run_git(tmp_path / "origin.git", "for-each-ref") == ""
    again = aipm(built, "merge", flags=["--json"])
    assert again.exit_code == 0
    assert json.loads(again.stdout)["data"]["nothing"] is True


def test_declining_merges_nothing(built: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    interactive(monkeypatch)
    before = head(built, "main")
    result = aipm(built, "merge", input="n\n")
    assert result.exit_code == 0, result.output
    assert "Nothing merged." in result.stdout
    assert head(built, "main") == before


def test_into_a_branch_checked_out_nowhere_moves_only_its_ref(
    built: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    run_git(built, "branch", "release", "main")
    interactive(monkeypatch)
    ok(aipm(built, "merge", "--into", "release", input="y\n"))
    assert head(built, "release") == head(built, "aipm/integration")
    assert head(built, "main") != head(built, "release")


def test_a_branch_with_its_own_commits_is_never_rewritten(built: Path) -> None:
    run_git(built, "commit", "-q", "--allow-empty", "-m", "my own work")
    before = head(built, "main")
    code, env = envelope(built)
    assert code == 2, env
    assert "cannot be fast-forwarded" in env["errors"][0]["message"]
    assert head(built, "main") == before


@pytest.mark.parametrize("target", ["aipm/integration", "aipm/task/T-002", "no-such-branch"])
def test_aipm_branches_and_missing_branches_are_refused(built: Path, target: str) -> None:
    code, env = envelope(built, "--into", target)
    assert code == 2, env


def test_a_branch_checked_out_in_another_worktree_is_refused(built: Path, tmp_path: Path) -> None:
    run_git(built, "branch", "elsewhere", "main")
    run_git(built, "worktree", "add", "-q", str(tmp_path / "other"), "elsewhere")
    code, env = envelope(built, "--into", "elsewhere")
    assert code == 2, env
    assert "checked out in" in env["errors"][0]["message"]


def test_a_branch_that_moved_after_the_log_was_shown_is_not_merged(built: Path) -> None:
    shown = merge_app.plan(built, into="main")
    before = head(built, "main")
    tip = head(built, "aipm/integration")
    newer = run_git(built, "commit-tree", f"{tip}^{{tree}}", "-p", tip, "-m", "another task")
    run_git(built, "update-ref", "refs/heads/aipm/integration", newer.strip(), tip)
    with pytest.raises(UsageError, match="moved since the log was shown"):
        merge_app.apply(built, shown)
    assert head(built, "main") == before


def test_status_shows_the_spend_against_the_budget(built: Path) -> None:
    result = ok(aipm(built, "status", flags=["--json"]))
    spend = json.loads(result.stdout)["data"]["spend"]
    assert spend["usd"] == pytest.approx(0.25)
    assert spend["budget_run_usd"] == 10.0
    assert spend["run_id"].startswith("r-")
    text = ok(aipm(built, "status")).stdout
    assert "Spend: $0.25 of $10.00 in the last build" in text


def test_a_planted_cost_record_is_not_believed(built: Path) -> None:
    planted = built / ".pm" / "runs" / "r-29991231-2359-ffff"
    planted.mkdir(parents=True)
    (planted / "cost.json").write_text(json.dumps({"spent_usd": 0.0, "tokens_used": 0}))
    spend = json.loads(ok(aipm(built, "status", flags=["--json"])).stdout)["data"]["spend"]
    assert spend["usd"] == pytest.approx(0.25)
