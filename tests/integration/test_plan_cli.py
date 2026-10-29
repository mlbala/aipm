"""`aipm plan` end to end with FakeLLM (build prompt 04).

The corpus cases (unknown gates, unsafe paths, cycles, oversized plans, escapes, package names)
are in tests/security/test_plan_corpus.py.
"""

import json
from collections.abc import Callable
from pathlib import Path
from typing import Any

import pytest

from aipm.domain.models import (
    ApprovalGate,
    ArtifactKind,
    OverrideReason,
    RoleName,
    TaskStatus,
)
from aipm.llm.fake import FakeLLM
from aipm.state.layout import repo_id
from aipm.state.store import open_store
from tests.integration.conftest import UserDirs
from tests.integration.flow import (
    aipm,
    approvals,
    designed,
    discovered,
    ok,
    pm_files,
    reply,
    tasks,
    use_responses,
)

type UseFake = Callable[[str], FakeLLM]
PLANNER = RoleName.PLANNER


@pytest.fixture
def repo(tmp_repo: Path, fake_llm: UseFake) -> Path:
    """Discovered and designed, G1 and G2 approved, no plan yet."""
    fake_llm("clinic")
    designed(tmp_repo)
    return tmp_repo


def planner_replies(*replies: dict[str, Any]) -> dict[RoleName, list[dict[str, Any]]]:
    return {PLANNER: [{"json": r} for r in replies]}


def trusted(user_dirs: UserDirs, repo: Path) -> bool:
    if not user_dirs.trust_file.exists():
        return False
    return repo_id(repo) in user_dirs.trust_file.read_text(encoding="utf-8")


# ---------------------------------------------------------------- preconditions


def test_plan_needs_an_approved_design(tmp_repo: Path, fake_llm: UseFake) -> None:
    fake_llm("clinic")
    designed(tmp_repo)
    store = open_store(tmp_repo)
    kept = [a for a in approvals(tmp_repo).approvals if a.gate is not ApprovalGate.G2]
    store.save(approvals(tmp_repo).model_copy(update={"approvals": kept}))
    result = aipm(tmp_repo, "plan")
    assert result.exit_code == 2
    assert "architecture.md has no G2 approval" in result.stderr
    assert not (tmp_repo / ".pm" / "tasks.yaml").exists()


def test_plan_before_design(tmp_repo: Path, fake_llm: UseFake) -> None:
    fake_llm("clinic")
    discovered(tmp_repo)
    result = aipm(tmp_repo, "plan")
    assert result.exit_code == 2
    assert "architecture.md is missing; run `aipm design --regenerate`" in result.stderr


@pytest.mark.parametrize("value", ["0", "201"])
def test_max_tasks_bounds(repo: Path, value: str) -> None:
    result = aipm(repo, "plan", "--max-tasks", value)
    assert result.exit_code == 2
    assert "--max-tasks must be between 1 and 200" in result.stderr


def test_plan_needs_a_gate_menu(repo: Path) -> None:
    config = repo / ".pm" / "config.yaml"
    text = config.read_text(encoding="utf-8")
    config.write_text(text.split("allowed_executables:")[0], encoding="utf-8")
    result = aipm(repo, "plan")
    assert result.exit_code == 2
    assert "there is no gate menu" in result.stderr


# ---------------------------------------------------------------- writing the plan


def test_plan_writes_tasks_and_worksheet(repo: Path, user_dirs: UserDirs) -> None:
    result = ok(aipm(repo, "plan", flags=["--yes"]))
    store = open_store(repo)
    doc = tasks(repo)
    assert [t.id for t in doc.tasks] == [f"T-{n:03d}" for n in range(1, 8)]
    assert doc.derived_from.prd == store.sha256(ArtifactKind.PRD)
    assert doc.derived_from.architecture == store.sha256(ArtifactKind.ARCHITECTURE)
    assert doc.derived_from.threat_model == store.sha256(ArtifactKind.THREAT_MODEL)
    by_id = {t.id: t for t in doc.tasks}
    assert by_id["T-004"].gates == ["lint", "unit", "ac_trace"], "the mandatory gate was added"
    assert [c.id for c in by_id["T-003"].acceptance] == ["AC-T003-1", "AC-T003-2"]
    worksheet = (repo / ".pm" / "worksheet.md").read_text(encoding="utf-8")
    assert "| T-003 | todo | security | M | T-002 |" in worksheet
    assert "Plan: 7 tasks, DAG depth 4, widest level 4; 1 change by the plan validator" in (
        result.stdout
    )
    assert "G3 (plan approval): approved" in result.stdout
    assert any(a.gate is ApprovalGate.G3 for a in approvals(repo).approvals)


def test_yes_records_g3_but_never_trust(repo: Path, user_dirs: UserDirs) -> None:
    result = ok(aipm(repo, "plan", flags=["--yes"]))
    assert "Execution surface trusted: no" in result.stdout
    assert "--yes never grants it" in result.stdout
    assert "aipm trust --confirm " in result.stdout
    assert not trusted(user_dirs, repo)
    phase = json.loads(ok(aipm(repo, flags=["--json"])).stdout)["data"]
    assert (phase["phase"], phase["next_command"]) == ("plan_draft", "aipm trust")


def test_without_yes_g3_is_pending(repo: Path) -> None:
    result = ok(aipm(repo, "plan"))
    assert "G3 (plan approval): pending" in result.stdout
    assert "aipm approve plan" in result.stdout
    assert not any(a.gate is ApprovalGate.G3 for a in approvals(repo).approvals)


def test_interactive_g3_records_trust(
    repo: Path, user_dirs: UserDirs, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr("aipm.cli.output.stdin_is_terminal", lambda: True)
    result = ok(aipm(repo, "plan", input="y\n"))
    assert "Approve the plan (G3) and trust these exact commands" in result.stdout
    assert (
        "unit (required): uv run --frozen --offline pytest -q --junitxml '{report_file}' "
        "'{test_paths}'"
    ) in result.stdout
    assert "Execution surface trusted: yes" in result.stdout
    assert trusted(user_dirs, repo)
    phase = json.loads(ok(aipm(repo, flags=["--json"])).stdout)["data"]
    assert (phase["phase"], phase["next_command"]) == ("plan_approved", "aipm prompt T-001")


def test_interactive_decline_records_nothing(
    repo: Path, user_dirs: UserDirs, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr("aipm.cli.output.stdin_is_terminal", lambda: True)
    result = ok(aipm(repo, "plan", input="n\n"))
    assert "G3 (plan approval): pending" in result.stdout
    assert not trusted(user_dirs, repo)


def test_json_output(repo: Path) -> None:
    env = json.loads(ok(aipm(repo, "plan", flags=["--json", "--yes"])).stdout)
    data = env["data"]
    assert data["tasks"] == 7
    assert data["changes"] == ["T-004: added the mandatory ac_trace gate"]
    assert data["plan"]["depth"] == 4
    assert data["plan"]["deps_add"] == [
        "T-001: pypi fastapi", "T-001: pypi sqlalchemy", "T-003: pypi slowapi",
    ]  # fmt: skip
    assert data["trusted"] is False


def test_plan_refuses_to_replace_a_started_plan(repo: Path, fake_llm: UseFake) -> None:
    ok(aipm(repo, "plan", flags=["--yes"]))
    doc = tasks(repo)
    doc.tasks[0] = doc.tasks[0].model_copy(update={"status": TaskStatus.IN_PROGRESS})
    open_store(repo).save(doc)
    fake = fake_llm("clinic")
    result = aipm(repo, "plan")
    assert result.exit_code == 2
    assert "work on the current plan has started" in result.stderr
    assert fake.requests == []


# ---------------------------------------------------------------- the repair attempt


def test_traceability_gets_one_repair(repo: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    bad = reply("planner")
    bad["tasks"][5]["traces"] = ["NFR-02"]  # T-006 no longer traces F-004
    fake = use_responses(monkeypatch, planner_replies(bad, reply("planner")))
    ok(aipm(repo, "plan"))
    first, second = fake.requests_for(PLANNER)
    assert "must feature F-004 is traced by no task" in second.user
    assert '<untrusted source="aipm:validator"' in second.user
    assert "Problems with your previous reply" not in first.user


def test_traceability_failing_twice_exits_1(repo: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    bad = reply("planner")
    bad["tasks"][3]["traces"] = ["F-001"]  # T-004 no longer traces F-003 or TM-03
    use_responses(monkeypatch, planner_replies(bad, bad))
    before = pm_files(repo)
    result = aipm(repo, "plan")
    assert result.exit_code == 1
    assert "the plan breaks 2 rules" in result.stderr
    assert json.loads(result.stdout)["issues"] == [
        "plan: must feature F-003 is traced by no task",
        "plan: threat TM-03 is traced by no task",
    ]
    assert pm_files(repo) == before


def test_max_tasks_is_a_validator_rule(repo: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    use_responses(monkeypatch, planner_replies(reply("planner"), reply("planner")))
    result = aipm(repo, "plan", "--max-tasks", "3")
    assert result.exit_code == 1
    assert json.loads(result.stdout)["issues"] == ["plan: at most 3 tasks (got 7)"]


# ---------------------------------------------------------------- stale input


def test_stale_input_needs_accept_stale_which_is_recorded(
    repo: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    path = repo / ".pm" / "architecture.md"
    path.write_text(path.read_text(encoding="utf-8") + "\nA hand edit.\n", encoding="utf-8")
    result = aipm(repo, "plan")
    assert result.exit_code == 2
    assert "architecture.md has no G2 approval" in result.stderr
    assert "threat-model.md is stale" in result.stderr
    fake = use_responses(monkeypatch, planner_replies(reply("planner")))
    ok(aipm(repo, "plan", "--accept-stale"))
    overrides = {(o.command, o.artifact, o.reason) for o in approvals(repo).overrides}
    assert overrides == {
        ("plan", "architecture.md", OverrideReason.UNAPPROVED),
        ("plan", "threat-model.md", OverrideReason.STALE),
    }
    (request,) = fake.requests_for(PLANNER)
    assert '<untrusted source="unapproved:architecture"' in request.user
    assert '<untrusted source="stale:threat_model"' in request.user
    assert '<untrusted source="approved:prd"' in request.user


def test_an_upstream_change_makes_the_plan_stale(repo: Path) -> None:
    ok(aipm(repo, "plan", flags=["--yes"]))
    path = repo / ".pm" / "threat-model.md"
    path.write_text(path.read_text(encoding="utf-8") + "\nEdited.\n", encoding="utf-8")
    data = json.loads(ok(aipm(repo, flags=["--json"])).stdout)["data"]
    assert data["stale"] == ["tasks"]
    assert data["impacts"] == [
        "threat-model.md changed after the plan was made → the plan is stale"
    ]
