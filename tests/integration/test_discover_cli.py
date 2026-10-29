"""`aipm discover` end to end with FakeLLM (build prompt 03).

The real gateway runs (redaction, schema validation, repair, budget); only the provider is the
FakeLLM. Interactive runs are covered in `test_discover_interactive.py`.
"""

import json
import shutil
from collections.abc import Callable
from pathlib import Path

import pytest
from click.testing import Result
from typer.testing import CliRunner

from aipm.cli.main import app
from aipm.domain.models import (
    AnswerSource,
    ApprovalsDoc,
    ArtifactKind,
    PrdDoc,
    RequirementsDoc,
    RoleName,
)
from aipm.llm.fake import FakeLLM
from aipm.state.store import open_store
from tests.conftest import REPO_ROOT
from tests.integration.conftest import UserDirs

runner = CliRunner()
IDEA = REPO_ROOT / "examples" / "clinic-booking" / "idea.md"
ANSWERS = REPO_ROOT / "tests" / "fakes" / "answers" / "clinic.yaml"

type UseFake = Callable[[str], FakeLLM]


def aipm(repo: Path, *args: str, flags: tuple[str, ...] = ()) -> Result:
    """Run aipm non-interactively against `repo`, with extra global `flags`."""
    return runner.invoke(app, ["--non-interactive", *flags, "-C", str(repo), *args])


IDEA_REL = "examples/clinic-booking/idea.md"
ANSWERS_REL = "tests/fakes/answers/clinic.yaml"


@pytest.fixture
def repo(tmp_repo: Path) -> Path:
    """An initialized repo holding the clinic idea and answers files at aipm's own paths."""
    assert runner.invoke(app, ["-C", str(tmp_repo), "init"]).exit_code == 0
    for source, rel in ((IDEA, IDEA_REL), (ANSWERS, ANSWERS_REL)):
        (tmp_repo / rel).parent.mkdir(parents=True, exist_ok=True)
        shutil.copy(source, tmp_repo / rel)
    return tmp_repo


def discover(repo: Path, *flags: str) -> Result:
    """Discover from the clinic idea with the clinic answers, by absolute paths."""
    idea, answers = str(repo / IDEA_REL), str(repo / ANSWERS_REL)
    return aipm(repo, "discover", "--from", idea, "--answers", answers, flags=flags)


def requirements(repo: Path) -> RequirementsDoc:
    doc = open_store(repo).load(ArtifactKind.REQUIREMENTS)
    assert isinstance(doc, RequirementsDoc)
    return doc


def prd(repo: Path) -> PrdDoc:
    doc = open_store(repo).load(ArtifactKind.PRD)
    assert isinstance(doc, PrdDoc)
    return doc


def test_definition_of_done_discover_from_idea_with_answers(
    repo: Path, fake_llm: UseFake, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The prompt's definition of done, run from the repository root exactly as written.

    aipm discover --from examples/clinic-booking/idea.md --answers tests/fakes/answers/clinic.yaml
    """
    fake = fake_llm("clinic")
    monkeypatch.chdir(repo)
    result = runner.invoke(
        app, ["--non-interactive", "discover", "--from", IDEA_REL, "--answers", ANSWERS_REL]
    )
    assert result.exit_code == 0, result.output

    doc = requirements(repo)
    assert doc.project.one_liner.startswith("Small clinics")
    assert doc.coverage.score == 1.0
    assert doc.coverage.rounds == 1
    extracted = [a for a in doc.answers if a.source is AnswerSource.FILE]
    assert len(extracted) == 6
    assert all(a.confirmed for a in extracted)
    from_answers = {a.dimension.value: a for a in doc.answers if a.source is AnswerSource.USER}
    assert set(from_answers) == {
        "integrations", "scale_performance", "security_compliance", "deployment_ops",
    }  # fmt: skip
    assert (
        from_answers["security_compliance"].answer
        == "GDPR; EU data residency; Staff login with 2FA"
    )
    assert [s.kind.value for s in doc.sources] == ["file", "answers"]
    assert doc.sources[0].path == IDEA_REL
    assert doc.open_questions == []

    document = prd(repo)
    assert document.meta.derived_from.requirements == open_store(repo).sha256(
        ArtifactKind.REQUIREMENTS
    )
    assert [f.id for f in document.meta.features] == ["F-001", "F-002", "F-003", "F-004", "F-005"]
    for heading in (
        "## Problem", "## Users", "## Goals and metrics", "## Scope", "## Features",
        "## Non-functional requirements", "## Out of scope", "## Assumptions", "## Open questions",
    ):  # fmt: skip
        assert heading in document.body
    assert (
        (repo / ".pm" / "requirements.md")
        .read_text(encoding="utf-8")
        .startswith("# Requirements: repo")
    )
    assert "G1 (PRD approval): pending" in result.stdout
    assert "aipm approve prd" in result.stdout
    assert not (repo / ".pm" / "approvals.yaml").exists()
    assert fake.remaining(RoleName.INTERVIEWER) == 0
    assert fake.remaining(RoleName.PRD_WRITER) == 0


def test_yes_approves_g1_and_never_writes_trust(
    repo: Path, fake_llm: UseFake, user_dirs: UserDirs
) -> None:
    fake_llm("clinic")
    result = discover(repo, "--yes")
    assert result.exit_code == 0, result.output
    assert "G1 (PRD approval): approved" in result.stdout
    approvals = open_store(repo).load(ArtifactKind.APPROVALS)
    assert isinstance(approvals, ApprovalsDoc)
    (approval,) = approvals.approvals
    assert approval.gate.value == "G1"
    assert approval.artifact == "prd.md"
    assert approval.sha256 == open_store(repo).sha256(ArtifactKind.PRD)
    assert not user_dirs.trust_file.exists()


def test_json_output_has_coverage_and_usage(repo: Path, fake_llm: UseFake) -> None:
    fake_llm("clinic")
    result = discover(repo, "--json")
    assert result.exit_code == 0, result.output
    (line,) = result.stdout.splitlines()
    data = json.loads(line)["data"]
    assert data["coverage"]["score"] == 1.0
    assert data["approval"] == "pending"
    assert data["usage"]["total_tokens"] > 0
    roles = {entry["role"] for entry in data["usage"]["by_role"]}
    assert roles == {"interviewer", "prd_writer"}


def write_answers(repo: Path, text: str, name: str = "answers.yaml") -> str:
    (repo / name).write_text(text, encoding="utf-8")
    return str(repo / name)


def test_without_input_a_fresh_project_asks_for_a_description(
    repo: Path, fake_llm: UseFake
) -> None:
    fake = fake_llm("pending")
    result = aipm(repo, "discover")
    assert result.exit_code == 4
    assert "a project description is needed" in result.stderr
    pending = json.loads(result.stdout)["pending"]
    assert [p["id"] for p in pending] == ["description"]
    assert fake.requests == []
    assert not (repo / ".pm" / "requirements.yaml").exists()


def test_pending_questions_exit_4_save_progress_and_resume(repo: Path, fake_llm: UseFake) -> None:
    fake = fake_llm("pending")
    first = write_answers(repo, "description: A booking app for a small clinic.\n")
    result = aipm(repo, "discover", "--answers", first)
    assert result.exit_code == 4, result.output
    pending = json.loads(result.stdout)["pending"]
    assert [p["id"] for p in pending] == ["Q-002", "Q-003"]
    assert pending[1]["default"] == ["Managed hosting in the EU"]
    saved = requirements(repo)
    assert [q.id for q in saved.open_questions] == ["Q-002", "Q-003"]
    assert saved.answers[0].question.startswith("Describe the project")
    assert not (repo / ".pm" / "prd.md").exists()

    second = write_answers(
        repo, "answers:\n  Q-002: about 80 a day\n  deployment_ops: Managed hosting in the EU\n",
        name="more.yaml",
    )  # fmt: skip
    result = aipm(repo, "discover", "--answers", second)
    assert result.exit_code == 0, result.output
    doc = requirements(repo)
    assert doc.open_questions == []
    assert {a.id: a.answer for a in doc.answers}["Q-002"] == "about 80 a day"
    assert prd(repo).meta.features
    assert fake.remaining(RoleName.INTERVIEWER) == 0


def test_json_envelope_carries_the_pending_questions(repo: Path, fake_llm: UseFake) -> None:
    fake_llm("pending")
    answers = write_answers(repo, "description: A booking app.\n")
    result = aipm(repo, "discover", "--answers", answers, flags=("--json",))
    assert result.exit_code == 4
    (line,) = result.stdout.splitlines()
    envelope = json.loads(line)
    assert envelope["errors"][0]["code"] == "PENDING_QUESTIONS"
    assert [p["id"] for p in envelope["data"]["pending"]] == ["Q-002", "Q-003"]


def test_defaults_become_unconfirmed_assumptions(repo: Path, fake_llm: UseFake) -> None:
    fake_llm("pending")
    answers = write_answers(repo, "description: A booking app.\nanswers: {Q-002: '80'}\n")
    result = aipm(repo, "discover", "--answers", answers, "--defaults")
    assert result.exit_code == 0, result.output
    doc = requirements(repo)
    (assumption,) = doc.assumptions
    assert assumption.id == "A-001"
    assert assumption.dimension.value == "deployment_ops"
    assert assumption.statement.startswith("Managed hosting in the EU (default for:")
    assert assumption.reason == "--defaults"
    assert not assumption.confirmed
    # An assumption is not user evidence: the clamp holds that dimension at 0.5.
    assert doc.coverage.by_dimension["deployment_ops"] == 0.5  # type: ignore[index]
    assert "A-001" in prd(repo).body


def test_edit_changes_one_answer_and_regenerates_the_prd(repo: Path, fake_llm: UseFake) -> None:
    fake_llm("clinic")
    assert discover(repo, "--yes").exit_code == 0
    old_prd = open_store(repo).sha256(ArtifactKind.PRD)
    fake = fake_llm("clinic")
    answers = write_answers(repo, "answers: {Q-007: A provider such as Twilio}\n")
    result = aipm(repo, "discover", "--edit", "Q-007", "--answers", answers)
    assert result.exit_code == 0, result.output
    edited = {a.id: a for a in requirements(repo).answers}["Q-007"]
    assert edited.answer == "A provider such as Twilio"
    assert edited.source is AnswerSource.USER
    assert open_store(repo).sha256(ArtifactKind.PRD) != old_prd
    assert fake.requests_for(RoleName.INTERVIEWER) == []
    assert "G1 (PRD approval): pending" in result.stdout


@pytest.mark.parametrize(
    ("args", "message"),
    [
        (("--edit", "Q-999"), "Q-999 is not an answered question"),
        (("--edit", "nope"), "--edit takes a question ID"),
        (("--threshold", "1.5"), "--threshold must be between 0 and 1"),
        (("--max-rounds", "0"), "--max-rounds must be between 1 and 20"),
    ],
)
def test_bad_flags_exit_2(
    repo: Path, fake_llm: UseFake, args: tuple[str, ...], message: str
) -> None:
    fake_llm("clinic")
    assert discover(repo).exit_code == 0
    result = aipm(repo, "discover", *args)
    assert result.exit_code == 2
    assert message in result.stderr


def test_edit_needs_the_new_answer_in_non_interactive_mode(repo: Path, fake_llm: UseFake) -> None:
    fake_llm("clinic")
    assert discover(repo).exit_code == 0
    result = aipm(repo, "discover", "--edit", "Q-001")
    assert result.exit_code == 4
    assert json.loads(result.stdout)["pending"][0]["id"] == "Q-001"


def test_invalid_model_output_twice_exits_1_and_writes_nothing(
    repo: Path, fake_llm: UseFake
) -> None:
    fake = fake_llm("invalid")
    before = sorted(p.name for p in (repo / ".pm").iterdir())
    result = discover(repo)
    assert result.exit_code == 1
    assert "failed validation twice, so nothing was written" in result.stderr
    assert len(fake.requests) == 2
    assert "<key>: Extra inputs are not permitted" not in fake.requests[0].user
    assert sorted(p.name for p in (repo / ".pm").iterdir()) == before


def test_token_budget_exceeded_exits_5(repo: Path, fake_llm: UseFake, user_dirs: UserDirs) -> None:
    fake = fake_llm("clinic")
    user_dirs.config.write_text("budget: {run_tokens: 1000}\n", encoding="utf-8")
    result = discover(repo)
    assert result.exit_code == 5
    assert "token budget" in result.stderr
    assert fake.requests == []


def test_input_files_outside_the_repo_or_too_large_are_refused(
    repo: Path, fake_llm: UseFake, tmp_path: Path, user_dirs: UserDirs
) -> None:
    fake_llm("clinic")
    outside = tmp_path / "idea.md"
    outside.write_text("idea", encoding="utf-8")
    result = aipm(repo, "discover", "--from", str(outside))
    assert result.exit_code == 2
    assert "outside the repository" in result.stderr
    result = aipm(repo, "discover", "--from", str(repo / ".pm" / "config.yaml"))
    assert result.exit_code == 6
    user_dirs.config.write_text("security: {max_input_kib: 1}\n", encoding="utf-8")
    result = discover(repo)
    assert result.exit_code == 2
    assert "is larger than 1024 bytes" in result.stderr
