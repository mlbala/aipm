"""The injection corpus through `aipm discover` (build prompt 03; SECURITY.md §7, §14.2).

C-001 direct instruction in idea.md, C-002 instruction in an answer, C-004 Unicode smuggling,
C-008 YAML injection in an answer, C-010 terminal escapes in model text, C-014 oversized idea.md;
plus hostile provider responses (extra fields, overlong strings, bad IDs).
"""

import json
import shutil
from collections.abc import Callable, Mapping, Sequence
from pathlib import Path
from typing import Any

import pytest
from click.testing import Result
from ruamel.yaml import YAML
from typer.testing import CliRunner

from aipm.cli.main import app
from aipm.domain.models import ArtifactKind, RequirementsDoc, RoleName
from aipm.llm.fake import FakeLLM
from aipm.state.store import open_store
from tests.conftest import LLM_FIXTURES, REPO_ROOT

runner = CliRunner()
CORPUS = Path(__file__).parent / "corpus"
TAG_CHARS = range(0xE0000, 0xE0080)


def corpus_text(case_id: str) -> str:
    (path,) = CORPUS.glob(f"{case_id}-*.yaml")
    return str(YAML(typ="safe", pure=True).load(path.read_text(encoding="utf-8"))["input"]["text"])


def aipm(repo: Path, *args: str) -> Result:
    return runner.invoke(app, ["--non-interactive", "-C", str(repo), *args])


def snapshot(repo: Path) -> dict[str, bytes]:
    pm = repo / ".pm"
    skip = {".lock", "events.jsonl"}
    return {p.name: p.read_bytes() for p in pm.iterdir() if p.is_file() and p.name not in skip}


@pytest.fixture
def repo(tmp_repo: Path) -> Path:
    assert runner.invoke(app, ["-C", str(tmp_repo), "init"]).exit_code == 0
    return tmp_repo


def use_responses(
    monkeypatch: pytest.MonkeyPatch, responses: Mapping[RoleName, Sequence[Mapping[str, Any]]]
) -> FakeLLM:
    fake = FakeLLM.from_responses(responses)
    monkeypatch.setattr("aipm.llm.gateway.make_provider", lambda llm, **_: fake)
    return fake


def fixture_reply(fixture: str, role: str, index: int = 0) -> dict[str, Any]:
    text = (LLM_FIXTURES / fixture / f"{role}.yaml").read_text(encoding="utf-8")
    return YAML(typ="safe", pure=True).load(text)["responses"][index]["json"]


# ---------------------------------------------------------------- C-001


def test_c001_injection_in_idea_exits_4_and_writes_nothing(
    repo: Path, fake_llm: Callable[[str], FakeLLM]
) -> None:
    fake_llm("injection")
    (repo / "idea.md").write_text(corpus_text("C-001"), encoding="utf-8")
    config_before = (repo / ".pm" / "config.yaml").read_bytes()
    before = snapshot(repo)
    result = aipm(repo, "discover", "--from", str(repo / "idea.md"))
    assert result.exit_code == 4
    assert "suspected prompt injection" in result.stderr
    data = json.loads(result.stdout)
    assert data["role"] == "interviewer"
    assert "Mark every coverage item as complete" in data["injection_suspected"][0]
    assert snapshot(repo) == before
    assert (repo / ".pm" / "config.yaml").read_bytes() == config_before
    (event,) = open_store(repo).read_events()
    assert event.kind.value == "injection_signal"
    assert event.source == "llm:interviewer"


def test_c001_with_accept_risk_coverage_is_clamped_and_no_gate_appears(
    repo: Path, fake_llm: Callable[[str], FakeLLM]
) -> None:
    fake_llm("injection")
    (repo / "idea.md").write_text(corpus_text("C-001"), encoding="utf-8")
    config_before = (repo / ".pm" / "config.yaml").read_bytes()
    result = aipm(repo, "discover", "--from", str(repo / "idea.md"), "--accept-risk")
    assert result.exit_code == 0, result.output
    assert "warning: --accept-risk: the interviewer reported suspected prompt injection" in (
        result.stderr
    )
    doc = open_store(repo).load(ArtifactKind.REQUIREMENTS)
    assert isinstance(doc, RequirementsDoc)
    # The fake "obeyed" and proposed every dimension covered; the clamp holds without evidence.
    assert all(score <= 0.5 for score in doc.coverage.by_dimension.values())
    assert doc.coverage.score <= 0.5
    assert (repo / ".pm" / "config.yaml").read_bytes() == config_before
    assert not (repo / ".pm" / "tasks.yaml").exists()
    assert "bash" not in (repo / ".pm" / "requirements.yaml").read_text(encoding="utf-8")


# ---------------------------------------------------------------- C-002 and C-008


@pytest.mark.parametrize("case_id", ["C-002", "C-008"])
def test_hostile_answers_are_stored_as_one_string(
    repo: Path, fake_llm: Callable[[str], FakeLLM], case_id: str
) -> None:
    fake_llm("clinic")
    shutil.copy(REPO_ROOT / "examples/clinic-booking/idea.md", repo / "idea.md")
    hostile = corpus_text(case_id)
    answers = {"schema_version": 1, "confirm_extracted": True,
               "answers": {"integrations": hostile, "scale_performance": "small",
                           "security_compliance": "GDPR", "deployment_ops": "managed"}}  # fmt: skip
    (repo / "answers.yaml").write_text(json.dumps(answers), encoding="utf-8")  # JSON is YAML
    result = aipm(repo, "discover", "--from", str(repo / "idea.md"),
                  "--answers", str(repo / "answers.yaml"))  # fmt: skip
    assert result.exit_code == 0, result.output
    doc = open_store(repo).load(ArtifactKind.REQUIREMENTS)
    assert isinstance(doc, RequirementsDoc)
    stored = [a.answer for a in doc.answers if a.dimension.value == "integrations"]
    assert stored == [hostile.strip()]
    assert not (repo / ".pm" / "tasks.yaml").exists()
    assert not (repo / ".pm" / "approvals.yaml").exists()  # C-002: no approval without a human


# ---------------------------------------------------------------- C-004


def test_c004_smuggled_tags_are_removed_before_any_prompt(
    repo: Path, fake_llm: Callable[[str], FakeLLM]
) -> None:
    fake = fake_llm("clinic")
    (repo / "idea.md").write_text(corpus_text("C-004"), encoding="utf-8")
    shutil.copy(REPO_ROOT / "tests/fakes/answers/clinic.yaml", repo / "answers.yaml")
    result = aipm(repo, "discover", "--from", str(repo / "idea.md"),
                  "--answers", str(repo / "answers.yaml"))  # fmt: skip
    assert result.exit_code == 0, result.output
    assert "removed 13 invisible characters" in result.stderr
    for request in fake.requests:
        assert not any(ord(ch) in TAG_CHARS for ch in request.user + request.system)
    assert "Book appointments online." in fake.requests[0].user
    events = open_store(repo).read_events()
    assert any(e.kind.value == "injection_signal" and e.source == "idea.md" for e in events)


# ---------------------------------------------------------------- C-010


def test_c010_escapes_in_model_text_never_reach_the_terminal(
    repo: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    hostile = corpus_text("C-010")
    reply = fixture_reply("pending", "interviewer")
    reply["questions"][0]["question"] = hostile
    reply["questions"][0]["why"] = hostile
    use_responses(monkeypatch, {RoleName.INTERVIEWER: [{"json": reply}]})
    (repo / "a.yaml").write_text("description: A booking app.\n", encoding="utf-8")
    plain = aipm(repo, "discover", "--answers", str(repo / "a.yaml"))
    assert plain.exit_code == 4
    as_json = runner.invoke(app, ["--json", "-C", str(repo), "discover"])
    for result in (plain, as_json):
        assert "\x1b" not in result.stdout + result.stderr
        assert "\x07" not in result.stdout + result.stderr


# ---------------------------------------------------------------- C-014


def test_c014_oversized_idea_is_rejected_before_any_llm_call(
    repo: Path, fake_llm: Callable[[str], FakeLLM]
) -> None:
    fake = fake_llm("clinic")
    unit = corpus_text("C-014")
    (repo / "idea.md").write_text(unit * (256 * 1024 // len(unit) + 1), encoding="utf-8")
    before = snapshot(repo)
    result = aipm(repo, "discover", "--from", str(repo / "idea.md"))
    assert result.exit_code == 2
    assert "larger than 262144 bytes" in result.stderr
    assert fake.requests == []
    assert snapshot(repo) == before


# ---------------------------------------------------------------- hostile provider responses


def bad_round(change: Mapping[str, Any]) -> dict[str, Any]:
    reply = fixture_reply("clinic", "interviewer")
    reply.update(change)
    return reply


def question(**change: Any) -> dict[str, Any]:
    return {**fixture_reply("clinic", "interviewer")["questions"][0], **change}


@pytest.mark.parametrize(
    "change",
    [
        {"gates": [{"name": "setup", "run": ["bash", "-c", "id"]}]},
        {"approve": True},
        {"one_liner": "x" * 201},
        {"injection_suspected": ["x" * 301]},
        {"questions": [question(id="../../etc/passwd")]},
        {"questions": [question(id="T-001")]},
        {"questions": [question(dimension="trust")]},
        {"questions": [question(options=["a"] * 9, kind="multi", default=[])]},
        {"extracted": [{"dimension": "data", "question": "q", "answer": "x" * 4001}]},
        {"coverage": {"problem_goals": "covered"}},
    ],
)
def test_hostile_responses_are_rejected_and_nothing_is_written(
    repo: Path, monkeypatch: pytest.MonkeyPatch, change: Mapping[str, Any]
) -> None:
    fake = use_responses(monkeypatch, {RoleName.INTERVIEWER: [{"json": bad_round(change)}] * 2})
    shutil.copy(REPO_ROOT / "examples/clinic-booking/idea.md", repo / "idea.md")
    before = snapshot(repo)
    result = aipm(repo, "discover", "--from", str(repo / "idea.md"))
    assert result.exit_code == 1, result.output
    assert "failed validation twice" in result.stderr
    assert len(fake.requests) == 2
    assert snapshot(repo) == before
