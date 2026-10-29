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
