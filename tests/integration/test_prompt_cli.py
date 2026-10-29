"""`aipm prompt <T-ID>` (build prompt 05; ARCHITECTURE §10.1, §12.7, §16)."""

import json
from collections.abc import Callable
from pathlib import Path

import pytest

from aipm.domain.models import (
    ApprovalGate,
    ApprovalsDoc,
    ArtifactKind,
    Done,
    TasksDoc,
    TaskStatus,
)
from aipm.execution.git import head_sha
from aipm.llm.fake import FakeLLM
from aipm.state.store import open_store
from tests.conftest import git_commit_all
from tests.integration.conftest import UserDirs
from tests.integration.flow import aipm, load, ok, planned, tasks


@pytest.fixture
def repo(tmp_repo: Path, fake_llm: Callable[[str], FakeLLM]) -> Path:
    fake_llm("clinic")
    planned(tmp_repo)
    return tmp_repo


def task_status(repo: Path, task_id: str) -> TaskStatus:
    return next(t.status for t in tasks(repo).tasks if t.id == task_id)


def set_status(repo: Path, task_id: str, status: TaskStatus) -> None:
    doc = tasks(repo)
    extra: dict[str, object] = {"status": status}
    if status is TaskStatus.DONE:
        extra["done"] = Done(commit="a" * 40, at="2026-10-29T10:00:00Z")  # type: ignore[arg-type]
    doc = doc.model_copy(update={"tasks": [t.model_copy(update=extra) if t.id == task_id else t
                                           for t in doc.tasks]})  # fmt: skip
    open_store(repo).save(doc)


def report_file(repo: Path, task_id: str = "T-001", status: str = "fail") -> Path:
    path = repo / "gate-report.json"
    path.write_text(json.dumps({"task": task_id, "gates": [
        {"name": "unit", "status": status, "summary": "1 failed",
         "output": "FAILED tests/test_app.py::test_health\nE   assert 500 == 200\n"}]}),
        encoding="utf-8")  # fmt: skip
    return path


# ---------------------------------------------------------------- trust and preconditions


def test_prompt_needs_trust(tmp_repo: Path, fake_llm: Callable[[str], FakeLLM]) -> None:
    fake_llm("clinic")
    planned(tmp_repo, trusted=False)
    before = (tmp_repo / ".pm" / "tasks.yaml").read_bytes()
    result = aipm(tmp_repo, "prompt", "T-001")
    assert result.exit_code == 6
    assert "aipm trust" in result.stderr
    assert result.stdout == ""
    assert not (tmp_repo / ".pm" / "prompts").exists()
    assert (tmp_repo / ".pm" / "tasks.yaml").read_bytes() == before


def test_prompt_needs_an_initialized_repository(tmp_repo: Path) -> None:
    result = aipm(tmp_repo, "prompt", "T-001")
    assert result.exit_code == 2
    assert "aipm init" in result.stderr


@pytest.mark.parametrize(
    ("args", "message"),
    [
        (["T-1"], "not a task ID"),
        (["T-099"], "no task T-099"),
        (["T-001", "--tool", "codex"], "v0.4"),
        (["T-001", "--tool", "cursor"], "unknown tool"),
        (["T-001", "--fix"], "--report FILE"),
        (["T-001", "--report", "r.json"], "--report goes with --fix"),
    ],
)
def test_usage_errors_exit_2(repo: Path, args: list[str], message: str) -> None:
    result = aipm(repo, "prompt", *args)
    assert result.exit_code == 2, result.output
    assert message in result.stderr


def test_unfinished_dependencies_need_force(repo: Path) -> None:
    result = aipm(repo, "prompt", "T-002")
    assert result.exit_code == 2
    assert "depends on tasks that are not done: T-001" in result.stderr
    forced = ok(aipm(repo, "prompt", "T-002", "--force"))
    assert "--force: T-002 started before T-001 finished" in forced.stderr
    assert task_status(repo, "T-002") is TaskStatus.IN_PROGRESS


@pytest.mark.parametrize("status", [TaskStatus.DONE, TaskStatus.SKIPPED])
def test_a_finished_task_is_refused(repo: Path, status: TaskStatus) -> None:
    set_status(repo, "T-001", status)
    result = aipm(repo, "prompt", "T-001", "--force")
    assert result.exit_code == 2
    assert f"T-001 is {status.value}" in result.stderr


def test_a_stale_plan_needs_accept_stale(repo: Path) -> None:
    prd = repo / ".pm" / "prd.md"
    prd.write_text(prd.read_text(encoding="utf-8") + "\nOne more line.\n", encoding="utf-8")
    result = aipm(repo, "prompt", "T-001")
    assert result.exit_code == 2
    assert "--accept-stale" in result.stderr
    accepted = ok(aipm(repo, "prompt", "T-001", "--accept-stale"))
    assert "--accept-stale: ran on prd.md" in accepted.stderr
    overrides = load(repo, ArtifactKind.APPROVALS, ApprovalsDoc).overrides
    assert {o.command for o in overrides} == {"prompt"}


# ---------------------------------------------------------------- the prompt


def test_prompt_prints_saves_and_starts_the_task(repo: Path) -> None:
    result = ok(aipm(repo, "prompt", "T-001"))
    saved = (repo / ".pm" / "prompts" / "T-001.claude.md").read_text(encoding="utf-8")
    assert result.stdout == saved
    assert saved.startswith("# Task T-001 for `repo`\n")
    assert "`uv run --frozen --offline pytest -q --junitxml /dev/null tests`" in saved
    assert "Saved .pm/prompts/T-001.claude.md; T-001 is in progress from" in result.stderr
    task = next(t for t in tasks(repo).tasks if t.id == "T-001")
    assert task.status is TaskStatus.IN_PROGRESS
    assert task.base_sha == head_sha(repo)
    worksheet = (repo / ".pm" / "worksheet.md").read_text(encoding="utf-8")
    assert "| T-001 | in_progress |" in worksheet


def test_g3_survives_the_status_change(repo: Path) -> None:
    ok(aipm(repo, "prompt", "T-001"))
    status = ok(aipm(repo, "status"))
    assert status.stdout.startswith("Phase: building\n")
    again = ok(aipm(repo, "approve", "plan", "--yes"))
    assert "G3 was already approved for this plan." in again.stdout
    assert ApprovalGate.G3 in {a.gate for a in load(repo, ArtifactKind.APPROVALS,
                                                       ApprovalsDoc).approvals}  # fmt: skip


def test_prompting_again_keeps_the_base_commit(repo: Path) -> None:
    ok(aipm(repo, "prompt", "T-001"))
    first = next(t.base_sha for t in tasks(repo).tasks if t.id == "T-001")
    assert first == head_sha(repo)
    git_commit_all(repo, "chore: work in progress")
    assert head_sha(repo) != first
    ok(aipm(repo, "prompt", "T-001"))
    assert next(t.base_sha for t in tasks(repo).tasks if t.id == "T-001") == first


def test_json_prints_one_envelope_with_the_prompt(repo: Path) -> None:
    result = ok(aipm(repo, "prompt", "T-001", flags=["--json"]))
    lines = result.stdout.splitlines()
    assert len(lines) == 1
    data = json.loads(lines[0])["data"]
    assert data["task"] == "T-001"
    assert data["file"] == ".pm/prompts/T-001.claude.md"
    assert data["status"] == "in_progress"
    assert data["prompt"].startswith("# Task T-001")
    assert data["bytes"] == len(data["prompt"].encode())


def test_out_writes_a_file_and_prints_no_prompt(repo: Path) -> None:
    result = ok(aipm(repo, "prompt", "T-001", "--out", str(repo / "prompt.md")))
    assert result.stdout == ""
    assert "and prompt.md" in result.stderr
    saved = (repo / ".pm" / "prompts" / "T-001.claude.md").read_text(encoding="utf-8")
    assert (repo / "prompt.md").read_text(encoding="utf-8") == saved


def test_copy_uses_the_clipboard_or_prints_a_hint(
    repo: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    copied: list[str] = []

    def fake_copy(text: str, **_: object) -> str:
        copied.append(text)
        return "pbcopy"

    monkeypatch.setattr("aipm.app.prompt.copy_text", fake_copy)
    result = ok(aipm(repo, "prompt", "T-001", "--copy"))
    assert copied == [result.stdout]
    assert "Copied with pbcopy." in result.stderr
    monkeypatch.setattr("aipm.app.prompt.copy_text", lambda text, **_: None)
    result = ok(aipm(repo, "prompt", "T-001", "--copy"))
    assert "No clipboard tool worked" in result.stderr


# ---------------------------------------------------------------- --fix


def test_fix_adds_the_failing_output(repo: Path) -> None:
    ok(aipm(repo, "prompt", "T-001"))
    result = ok(aipm(repo, "prompt", "T-001", "--fix", "--report", str(report_file(repo))))
    assert "## Previous attempt" in result.stdout
    assert '<untrusted source="gate-output:unit"' in result.stdout
    assert "E   assert 500 == 200" in result.stdout


def test_fix_needs_a_task_in_progress(repo: Path) -> None:
    result = aipm(repo, "prompt", "T-001", "--fix", "--report", str(report_file(repo)))
    assert result.exit_code == 2
    assert "--fix is for a task in progress" in result.stderr


@pytest.mark.parametrize(
    ("task_id", "status", "message"),
    [("T-002", "fail", "the report of T-002"), ("T-001", "pass", "no failing check")],
)
def test_fix_refuses_a_report_that_does_not_fit(
    repo: Path, task_id: str, status: str, message: str
) -> None:
    ok(aipm(repo, "prompt", "T-001"))
    result = aipm(repo, "prompt", "T-001", "--fix", "--report",
                  str(report_file(repo, task_id, status)))  # fmt: skip
    assert result.exit_code == 2
    assert message in result.stderr


def test_fix_refuses_a_malformed_report(repo: Path) -> None:
    ok(aipm(repo, "prompt", "T-001"))
    bad = repo / "bad.json"
    bad.write_text(json.dumps({"task": "T-001", "gates": [{"name": "unit"}], "x": 1}),
                   encoding="utf-8")  # fmt: skip
    result = aipm(repo, "prompt", "T-001", "--fix", "--report", str(bad))
    assert result.exit_code == 2
    assert "is not a gate report" in result.stderr


def test_the_user_trust_store_is_untouched(repo: Path, user_dirs: UserDirs) -> None:
    before = user_dirs.trust_file.read_bytes()
    ok(aipm(repo, "prompt", "T-001"))
    assert user_dirs.trust_file.read_bytes() == before
    assert isinstance(tasks(repo), TasksDoc)
