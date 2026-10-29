"""The clinic-booking example end to end with FakeLLM (build prompt 04).

init → discover → design → plan → approve plan → trust → status, from the repository root, as a
user would type it. The real gateway, validator, store and trust store run; only the LLM
provider is FakeLLM (tests/fakes/llm_fixtures/clinic/).
"""

import json
import shutil
from collections.abc import Callable
from pathlib import Path

import pytest
from click.testing import Result
from typer.testing import CliRunner

from aipm.cli.main import app
from aipm.llm.fake import FakeLLM
from tests.conftest import REPO_ROOT
from tests.integration.conftest import UserDirs, user_dirs  # noqa: F401 - isolates HOME and trust

runner = CliRunner()
IDEA = "examples/clinic-booking/idea.md"
ANSWERS = "tests/fakes/answers/clinic.yaml"


def aipm(*args: str) -> Result:
    result = runner.invoke(app, ["--non-interactive", *args])
    assert result.exit_code == 0, f"aipm {' '.join(args)}\n{result.output}"
    return result


def test_clinic_booking_from_idea_to_an_approved_plan(
    tmp_repo: Path,
    fake_llm: Callable[[str], FakeLLM],
    monkeypatch: pytest.MonkeyPatch,
    user_dirs: UserDirs,  # noqa: F811 - the imported fixture
) -> None:
    fake = fake_llm("clinic")
    monkeypatch.chdir(tmp_repo)

    aipm("init")
    # Added after init, as in step 03's definition of done, so the repository stays greenfield.
    for rel in (IDEA, ANSWERS):
        (tmp_repo / rel).parent.mkdir(parents=True, exist_ok=True)
        shutil.copy(REPO_ROOT / rel, tmp_repo / rel)
    discover = aipm("--yes", "discover", "--from", IDEA, "--answers", ANSWERS)
    assert "G1 (PRD approval): approved" in discover.stdout

    design = aipm("design")
    assert "G2 (design approval): pending" in design.stdout
    assert "Approve" not in design.stdout
    g2 = aipm("approve", "design", "--yes")
    assert "Copied the python-uv stack's prepare step" in g2.stdout

    plan = aipm("plan")
    assert "Plan: 7 tasks, DAG depth 4, widest level 4; 1 change by the plan validator" in (
        plan.stdout
    )
    assert "G3 (plan approval): pending" in plan.stdout

    g3 = aipm("approve", "plan", "--yes")
    assert "Trust is not recorded by --yes" in g3.stdout
    surface = json.loads(aipm("--json", "trust", "--show").stdout)["data"]["surface_hash"]
    aipm("trust", "--confirm", surface[:12])

    status = aipm("status")
    out = status.stdout
    assert out.startswith("Phase: plan_approved\nNext: aipm prompt T-001\n")
    assert "Tasks: 7 (todo 7, in progress 0, blocked 0, done 0, skipped 0)" in out
    assert "Security events: none unacknowledged" in out

    phase = json.loads(aipm("--json").stdout)["data"]
    assert (phase["phase"], phase["ready_task"]) == ("plan_approved", "T-001")
    roles = [r.role.value for r in fake.requests]
    assert roles == ["interviewer", "interviewer", "prd_writer", "architect", "threat_modeler",
                     "planner"]  # fmt: skip
    for name in ("architecture.md", "threat-model.md", "tasks.yaml", "worksheet.md"):
        assert (tmp_repo / ".pm" / name).is_file()
    assert sorted(p.name for p in (tmp_repo / ".pm" / "adr").iterdir()) == [
        "0001-fastapi-and-postgres-in-one-container.md",
        "0002-one-time-codes-by-whatsapp-for-patients.md",
    ]


def aipm_exit(code: int, *args: str) -> Result:
    result = runner.invoke(app, ["--non-interactive", *args])
    assert result.exit_code == code, f"aipm {' '.join(args)}\n{result.output}"
    return result


def test_v01_acceptance_from_idea_to_prompt_and_context_files(
    tmp_repo: Path,
    fake_llm: Callable[[str], FakeLLM],
    monkeypatch: pytest.MonkeyPatch,
    user_dirs: UserDirs,  # noqa: F811 - the imported fixture
) -> None:
    """ARCHITECTURE §22, v0.1 criterion 1: init → discover --answers → design → plan → trust
    --confirm → prompt T-001 → sync-context, with FakeLLM; prompt and sync-context exit 6
    before trust (SECURITY.md §6 rule 3)."""
    fake = fake_llm("clinic")
    monkeypatch.chdir(tmp_repo)
    aipm("init")
    for rel in (IDEA, ANSWERS):
        (tmp_repo / rel).parent.mkdir(parents=True, exist_ok=True)
        shutil.copy(REPO_ROOT / rel, tmp_repo / rel)
    aipm("--yes", "discover", "--from", IDEA, "--answers", ANSWERS)
    aipm("--yes", "design")
    aipm("--yes", "plan")

    # Before trust: no gate argv reaches a prompt or a context file.
    for args in (("prompt", "T-001"), ("sync-context",), ("approve", "context", "--yes")):
        refused = aipm_exit(6, *args)
        assert "aipm trust" in refused.stderr
    assert not (tmp_repo / "AGENTS.md").exists()
    assert not (tmp_repo / ".pm" / "prompts").exists()

    surface = json.loads(aipm("--json", "trust", "--show").stdout)["data"]["surface_hash"]
    aipm("trust", "--confirm", surface[:12])

    prompt = aipm("prompt", "T-001")
    assert prompt.stdout.startswith("# Task T-001 for `repo`\n")
    assert "- MUST NOT modify `.pm/**`" in prompt.stdout
    assert "`uv run --frozen --offline ruff check`" in prompt.stdout
    assert (tmp_repo / ".pm" / "prompts" / "T-001.claude.md").read_text(encoding="utf-8") == (
        prompt.stdout
    )

    aipm_exit(4, "sync-context")
    aipm("approve", "context", "--yes")
    aipm("sync-context")
    aipm("sync-context", "--check")
    agents = (tmp_repo / "AGENTS.md").read_text(encoding="utf-8")
    claude = (tmp_repo / "CLAUDE.md").read_text(encoding="utf-8")
    assert "## How to run checks" in agents
    assert "\n@AGENTS.md\n" in claude

    status = aipm("status").stdout
    assert status.startswith("Phase: building\n")
    assert "Tasks: 7 (todo 6, in progress 1, blocked 0, done 0, skipped 0)" in status
    roles = [r.role.value for r in fake.requests]
    assert roles == ["interviewer", "interviewer", "prd_writer", "architect", "threat_modeler",
                     "planner"]  # fmt: skip
