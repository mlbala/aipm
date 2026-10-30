"""Acceptance-criteria reviewer: veto only (ADR-0007, ARCHITECTURE §13.3, §14.1).

Input: the task's acceptance criteria and the diff, both wrapped as `Untrusted` (the criteria
come from the approved plan, the diff from the agent), plus the gate results by name and status
only. Output: a verdict per criterion, `met`, `not_met` or `unclear`, with at most 500
characters of evidence. A `not_met` fails the task; `met` adds nothing; nothing in the reply is
ever run. `postprocess` keeps one verdict per known criterion and calls a missing one unclear.
"""

from dataclasses import dataclass
from enum import StrEnum
from typing import Annotated, ClassVar

from pydantic import Field, StringConstraints

from aipm.domain.models import RoleName, StrictModel
from aipm.domain.models.base import AcceptanceId
from aipm.llm.gateway import RenderedPrompt
from aipm.roles.base import render_prompt
from aipm.security.untrusted import NonceFactory, Untrusted

TEMPLATE_VERSION = "1"

Excerpt = Annotated[str, StringConstraints(max_length=300)]
Evidence = Annotated[str, StringConstraints(max_length=500)]


class Verdict(StrEnum):
    """The reviewer's view of one criterion."""

    MET = "met"
    NOT_MET = "not_met"
    UNCLEAR = "unclear"


class CriterionVerdict(StrictModel):
    """One criterion's verdict and the evidence for it (T2)."""

    id: AcceptanceId
    verdict: Verdict
    evidence: Evidence = ""


class ACReview(StrictModel):
    """The reviewer's output."""

    criteria: list[CriterionVerdict] = Field(max_length=10)
    injection_suspected: list[Excerpt] = Field(max_length=10)


@dataclass(frozen=True, slots=True)
class ReviewedCriterion:
    """A criterion: its ID (aipm's) and its text (wrapped)."""

    id: str
    text: Untrusted


@dataclass(frozen=True, slots=True)
class ACReviewInput:
    """The criteria, the diff and the gate results for one task."""

    task_id: str
    criteria: tuple[ReviewedCriterion, ...]
    diff: Untrusted
    diff_cut: bool
    gates: tuple[tuple[str, str], ...]


class ACReviewer:
    """The AC reviewer role."""

    name: ClassVar[RoleName] = RoleName.AC_REVIEWER
    template_version: ClassVar[str] = TEMPLATE_VERSION
    output_schema: ClassVar[type[ACReview]] = ACReview

    def __init__(self, *, nonce: NonceFactory | None = None) -> None:
        self._nonce = nonce

    def render(self, inp: ACReviewInput) -> RenderedPrompt:
        """Render the system prompt, the criteria, the gate results and the diff."""
        context: dict[str, object] = {
            "task_id": inp.task_id,
            "criteria": [{"id": c.id, "text": c.text} for c in inp.criteria],
            "gates": [{"name": n, "status": s} for n, s in inp.gates],
            "diff": inp.diff,
            "diff_cut": inp.diff_cut,
        }
        return render_prompt(self.name, context, nonce=self._nonce)

    def postprocess(self, out: ACReview, inp: ACReviewInput) -> ACReview:
        """One verdict per criterion of the task, in its order; a missing one is unclear."""
        given: dict[str, CriterionVerdict] = {}
        for item in out.criteria:
            given.setdefault(item.id, item)
        criteria = [
            given.get(c.id)
            or CriterionVerdict(id=c.id, verdict=Verdict.UNCLEAR, evidence="no verdict given")
            for c in inp.criteria
        ]
        return out.model_copy(update={"criteria": criteria})


def create(*, nonce: NonceFactory | None = None) -> ACReviewer:
    """Return the role."""
    return ACReviewer(nonce=nonce)
