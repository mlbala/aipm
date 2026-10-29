"""`aipm approve prd` (build prompt 03): a record pinned to the PRD's hash, never trust."""

import json
import shutil
from collections.abc import Callable
from pathlib import Path

import pytest
from click.testing import Result
from typer.testing import CliRunner

from aipm.app import approve
from aipm.cli.main import app
from aipm.domain.models import ApprovalsDoc, ArtifactKind, Dimension, OpenQuestion, RequirementsDoc
from aipm.llm.fake import FakeLLM
from aipm.state.store import open_store
from tests.conftest import REPO_ROOT
from tests.integration.conftest import UserDirs

runner = CliRunner()


def aipm(repo: Path, *args: str) -> Result:
    return runner.invoke(app, ["--non-interactive", "-C", str(repo), *args])


@pytest.fixture
def repo(tmp_repo: Path, fake_llm: Callable[[str], FakeLLM]) -> Path:
    """A repo where discover has written requirements and an unapproved PRD."""
    assert runner.invoke(app, ["-C", str(tmp_repo), "init"]).exit_code == 0
    shutil.copy(REPO_ROOT / "examples/clinic-booking/idea.md", tmp_repo / "idea.md")
    shutil.copy(REPO_ROOT / "tests/fakes/answers/clinic.yaml", tmp_repo / "answers.yaml")
    fake_llm("clinic")
    result = aipm(tmp_repo, "discover", "--from", str(tmp_repo / "idea.md"),
                  "--answers", str(tmp_repo / "answers.yaml"))  # fmt: skip
    assert result.exit_code == 0, result.output
    return tmp_repo


def approvals(repo: Path) -> ApprovalsDoc:
    doc = open_store(repo).load(ArtifactKind.APPROVALS)
    assert isinstance(doc, ApprovalsDoc)
    return doc


def test_non_interactive_approval_needs_yes(repo: Path) -> None:
    result = aipm(repo, "approve", "prd")
    assert result.exit_code == 4
    assert "aipm approve prd --yes" in result.stderr
    assert "F-001 (must): Book an appointment" in result.stdout
    assert not (repo / ".pm" / "approvals.yaml").exists()


def test_yes_records_g1_once_and_never_trust(repo: Path, user_dirs: UserDirs) -> None:
    result = aipm(repo, "approve", "prd", "--yes")
    assert result.exit_code == 0, result.output
    assert "G1 approved." in result.stdout
    (entry,) = approvals(repo).approvals
    assert entry.gate.value == "G1"
    assert entry.sha256 == open_store(repo).sha256(ArtifactKind.PRD)
    assert entry.by
    again = runner.invoke(app, ["--non-interactive", "--yes", "-C", str(repo), "approve", "prd"])
    assert again.exit_code == 0
    assert "already approved" in again.stdout
    assert len(approvals(repo).approvals) == 1
    assert not user_dirs.trust_file.exists()


def test_json_output(repo: Path) -> None:
    result = runner.invoke(app, ["--json", "-C", str(repo), "approve", "prd", "--yes"])
    assert result.exit_code == 0
    data = json.loads(result.stdout)["data"]
    assert data["approved"] is True
    assert data["recorded"] is True
    assert data["sha256"] == open_store(repo).sha256(ArtifactKind.PRD)


def test_interactive_approval(repo: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr("aipm.cli.output.stdin_is_terminal", lambda: True)
    declined = runner.invoke(app, ["-C", str(repo), "approve", "prd"], input="n\n")
    assert declined.exit_code == 0
    assert "Not approved." in declined.stdout
    assert not (repo / ".pm" / "approvals.yaml").exists()
    accepted = runner.invoke(app, ["-C", str(repo), "approve", "prd"], input="y\n")
    assert accepted.exit_code == 0, accepted.output
    assert len(approvals(repo).approvals) == 1


def test_a_stale_prd_cannot_be_approved(repo: Path) -> None:
    store = open_store(repo)
    doc = store.load(ArtifactKind.REQUIREMENTS)
    assert isinstance(doc, RequirementsDoc)
    store.save(
        doc.model_copy(update={"project": doc.project.model_copy(update={"one_liner": "x"})})
    )
    result = aipm(repo, "approve", "prd", "--yes")
    assert result.exit_code == 2
    assert "prd.md is stale" in result.stderr


def test_blocking_open_questions_block_g1(repo: Path) -> None:
    store = open_store(repo)
    doc = store.load(ArtifactKind.REQUIREMENTS)
    assert isinstance(doc, RequirementsDoc)
    blocking = OpenQuestion(id="Q-050", dimension=Dimension.DATA, question="Retention?",
                            blocking=True)  # fmt: skip
    sha = store.save(doc.model_copy(update={"open_questions": [blocking]}))
    prd_text = (repo / ".pm" / "prd.md").read_text(encoding="utf-8")
    old = prd_text.split("requirements: ", 1)[1][:64]
    (repo / ".pm" / "prd.md").write_text(prd_text.replace(old, sha), encoding="utf-8")
    result = aipm(repo, "approve", "prd", "--yes")
    assert result.exit_code == 2
    assert "blocked by open questions: Q-050" in result.stderr


def test_a_prd_changed_after_review_is_not_approved(
    repo: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    real = approve.review_prd

    def review_then_tamper(project: Path | None) -> approve.PrdReview:
        review = real(project)
        path = repo / ".pm" / "prd.md"
        path.write_text(path.read_text(encoding="utf-8") + "\nAdded later.\n", encoding="utf-8")
        return review

    monkeypatch.setattr(approve, "review_prd", review_then_tamper)
    result = aipm(repo, "approve", "prd", "--yes")
    assert result.exit_code == 2
    assert "changed after it was shown" in result.stderr


@pytest.mark.parametrize(
    ("artifact", "prompt"), [("design", "04"), ("plan", "04"), ("context", "05")]
)
def test_later_artifacts_are_not_implemented_yet(repo: Path, artifact: str, prompt: str) -> None:
    result = aipm(repo, "approve", artifact, "--yes")
    assert result.exit_code == 2
    assert f"not implemented yet (build prompt {prompt})" in result.stderr


def test_approve_without_a_prd(tmp_repo: Path) -> None:
    assert runner.invoke(app, ["-C", str(tmp_repo), "init"]).exit_code == 0
    result = aipm(tmp_repo, "approve", "prd", "--yes")
    assert result.exit_code == 2
    assert "Run `aipm discover` first" in result.stderr
