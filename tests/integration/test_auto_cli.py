"""`aipm auto` end to end (ARCHITECTURE §7.3, §22 v0.4; ADR-0028), with the fake LLM and the stub
Claude Code: it runs the next step until the plan is built, and stops at the trust gate."""

import json
from collections.abc import Callable
from pathlib import Path
from typing import Any

import pytest

from aipm.domain.models import TaskStatus
from aipm.llm.fake import FakeLLM
from tests.conftest import FakeSecrets
from tests.integration.build_flow import (
    agent_stderr,
    calls,
    copy_t002,
    fake_registry,
    prepare_project,
    scenario,
)
from tests.integration.conftest import UserDirs
from tests.integration.flow import aipm, ok, planned, tasks

pytestmark = pytest.mark.usefixtures("allow_unix_sockets")


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
    return prepare_project(tmp_repo, monkeypatch, user_dirs.home)


def auto(repo: Path, *args: str) -> tuple[int, dict[str, Any]]:
    result = aipm(repo, "auto", *args, flags=["--json"])
    lines = result.stdout.splitlines()
    assert len(lines) == 1, f"--json prints exactly one object: {result.stdout!r}"
    return result.exit_code, json.loads(lines[0])


def skip_all_but_t002(repo: Path) -> None:
    for task in tasks(repo).tasks:
        if task.id != "T-002" and task.status is TaskStatus.TODO:
            ok(aipm(repo, "task", "skip", task.id, "--reason", "not in this test"))


def test_auto_builds_the_ready_tasks_until_the_plan_is_built(
    project: Path, user_dirs: UserDirs
) -> None:
    skip_all_but_t002(project)
    scenario(user_dirs.home, {"T-002": [{"steps": copy_t002()}]})
    code, envelope = auto(project, "--yes")
    assert code == 0, envelope
    assert envelope["data"] == {"ran": ["aipm build"], "phase": "built"}
    assert {t.id: t.status for t in tasks(project).tasks}["T-002"] is TaskStatus.DONE
    assert len(calls(user_dirs.home)) == 1
    assert "STUB-ASSERTION-FAILED" not in agent_stderr(project)


def test_auto_stops_when_a_build_blocks_a_task(project: Path, user_dirs: UserDirs) -> None:
    skip_all_but_t002(project)
    scenario(user_dirs.home, {"T-002": [{"text": "AIPM-DONE"}]})
    code, envelope = auto(project, "--yes", "--max-retries", "1")
    assert code == 3, envelope
    assert "aipm build" in envelope["errors"][0]["message"]


def test_dry_run_builds_nothing_and_stops_after_the_build_step(
    project: Path, user_dirs: UserDirs
) -> None:
    scenario(user_dirs.home, {"T-002": [{"steps": copy_t002()}]})
    code, envelope = auto(project, "--yes", "--dry-run")
    assert code == 0, envelope
    assert envelope["data"]["ran"] == ["aipm build"]
    assert calls(user_dirs.home) == []


def test_auto_on_the_sample_stops_at_the_trust_gate(
    tmp_repo: Path,
    fake_llm: Callable[[str], FakeLLM],
    fake_secrets: FakeSecrets,
    user_dirs: UserDirs,
) -> None:
    """ARCHITECTURE §22, v0.4: `aipm auto --yes` on the sample stops at the trust gate."""
    del fake_secrets
    fake_llm("clinic")
    planned(tmp_repo, trusted=False)
    result = aipm(tmp_repo, "auto", flags=["--yes"])
    assert result.exit_code == 6, result.output
    assert "aipm trust" in result.stderr
    assert "never records trust" in result.stderr
    assert not user_dirs.trust_file.exists()


def test_a_gate_pauses_a_non_interactive_run(
    tmp_repo: Path,
    fake_llm: Callable[[str], FakeLLM],
    fake_secrets: FakeSecrets,
) -> None:
    """Without --yes, `auto` exits 4 at a review gate and names the command."""
    del fake_secrets
    fake_llm("clinic")
    planned(tmp_repo)
    pm = tmp_repo / ".pm" / "approvals.yaml"
    pm.unlink()  # every gate open again
    result = aipm(tmp_repo, "auto")
    assert result.exit_code == 4, result.output
    assert "aipm approve prd --yes" in result.stderr
