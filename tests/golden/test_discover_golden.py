"""Golden snapshots: the rendered role prompts, `requirements.md` and `prd.md` (build prompt 03).

Nonces are fixed, so the snapshots are byte-stable. Update them only when a template or view
change is intended, and say so in the commit message (AGENTS.md).
"""

from typing import Any

from ruamel.yaml import YAML
from syrupy.assertion import SnapshotAssertion

from aipm.domain.coverage import ProposedStatus, compute_coverage
from aipm.domain.models import (
    Answer,
    AnswerSource,
    Assumption,
    Dimension,
    Mode,
    OpenQuestion,
    ProjectInfo,
    RequirementsDoc,
    Source,
    SourceKind,
)
from aipm.reporting.requirements_view import render_requirements_md
from aipm.roles import interviewer, prd_writer
from aipm.security.untrusted import Untrusted
from aipm.state import frontmatter
from tests.conftest import LLM_FIXTURES, REPO_ROOT


def nonce() -> str:
    return "u0123abcd"


def reply(role: str) -> dict[str, Any]:
    text = (LLM_FIXTURES / "clinic" / f"{role}.yaml").read_text(encoding="utf-8")
    return YAML(typ="safe", pure=True).load(text)["responses"][0]["json"]


def requirements() -> RequirementsDoc:
    doc = RequirementsDoc(
        project=ProjectInfo(name="clinic-booking", one_liner="Book online, remind on WhatsApp."),
        mode=Mode.GREENFIELD,
        sources=[Source(kind=SourceKind.FILE, path="idea.md", sha256="ab" * 32)],
        answers=[
            Answer(id="Q-001", dimension=Dimension.PROBLEM_GOALS, question="What problem?",
                   answer="Phones are busy.\nNo-shows are 15%.", source=AnswerSource.FILE,
                   confirmed=True),
            Answer(id="Q-002", dimension=Dimension.INTEGRATIONS, question="Which provider?",
                   answer="Meta WhatsApp Cloud API", source=AnswerSource.USER, confirmed=True),
            Answer(id="Q-003", dimension=Dimension.DATA, question="Retention?",
                   answer="12 months", source=AnswerSource.FILE, confirmed=False),
        ],
        assumptions=[
            Assumption(id="A-001", dimension=Dimension.DEPLOYMENT_OPS,
                       statement="Managed hosting (default for: Where?)", reason="--defaults"),
        ],
        open_questions=[
            OpenQuestion(id="Q-004", dimension=Dimension.SCALE_PERFORMANCE,
                         question="How many bookings a day?", blocking=True),
        ],
    )  # fmt: skip
    proposals = {
        Dimension.PROBLEM_GOALS: ProposedStatus.COVERED,
        Dimension.INTEGRATIONS: ProposedStatus.COVERED,
        Dimension.DATA: ProposedStatus.COVERED,
        Dimension.DEPLOYMENT_OPS: ProposedStatus.PARTIAL,
    }
    return doc.model_copy(update={"coverage": compute_coverage(doc, proposals, rounds=2)})


def test_interviewer_prompt(snapshot: SnapshotAssertion) -> None:
    doc = requirements()
    prompt = interviewer.create(nonce=nonce).render(
        interviewer.InterviewerInput(
            project="clinic-booking",
            round=3,
            extract=True,
            questions_per_round=4,
            scores=dict(doc.coverage.by_dimension),
            requirements=Untrusted("answers:\n  - id: Q-001\n", source="draft:requirements"),
            used_ids=frozenset({"Q-001", "Q-002", "Q-003", "Q-004"}),
            idea=Untrusted(
                (REPO_ROOT / "examples/clinic-booking/idea.md").read_text(encoding="utf-8"),
                source="file:examples/clinic-booking/idea.md",
            ),
            repo_map=Untrusted("src/\n  app.py\n", source="repo-map.md"),
        )
    )
    assert prompt.system == snapshot(name="interviewer.system")
    assert prompt.user == snapshot(name="interviewer.user")


def test_prd_writer_prompt(snapshot: SnapshotAssertion) -> None:
    prompt = prd_writer.create(nonce=nonce).render(
        prd_writer.PrdWriterInput(
            project="clinic-booking",
            requirements=Untrusted("schema_version: 1\nanswers: []\n", source="draft:requirements"),
        )
    )
    assert prompt.system == snapshot(name="prd_writer.system")
    assert prompt.user == snapshot(name="prd_writer.user")


def test_requirements_md(snapshot: SnapshotAssertion) -> None:
    assert render_requirements_md(requirements()) == snapshot(name="requirements.md")


def test_prd_md(snapshot: SnapshotAssertion) -> None:
    draft = prd_writer.PrdDraft.model_validate(reply("prd_writer"))
    prd = prd_writer.build_prd(draft, requirements(), requirements_sha="cd" * 32)
    assert frontmatter.dump(prd.front_matter(), prd.body) == snapshot(name="prd.md")
