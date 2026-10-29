"""Requirements interviewer (ARCHITECTURE §8, §14.1).

Input: the requirements so far (which hold the user's description), the idea file and the repo
map, all passed as `Untrusted`, plus the checklist scores aipm computed (T0). Output: an
`InterviewRound` with extracted answers, the next questions, a proposed status per dimension and
`injection_suspected`. The proposed statuses are only proposals: `aipm.domain.coverage` scores
and clamps them. Question IDs the model picks are checked for format here and renumbered by
`postprocess`, so aipm, not the model, allocates IDs.
"""

from dataclasses import dataclass
from enum import StrEnum
from typing import Annotated, ClassVar, Self

from pydantic import Field, StringConstraints, model_validator

from aipm.domain.coverage import NEEDS, WEIGHTS, ProposedStatus
from aipm.domain.ids import next_id
from aipm.domain.models import Dimension, RoleName, StrictModel
from aipm.domain.models.base import QuestionId
from aipm.llm.gateway import RenderedPrompt
from aipm.roles.base import render_prompt
from aipm.security.untrusted import NonceFactory, Untrusted

TEMPLATE_VERSION = "1"

QuestionText = Annotated[str, StringConstraints(min_length=1, max_length=300)]
AnswerText = Annotated[str, StringConstraints(min_length=1, max_length=4000)]
OptionText = Annotated[str, StringConstraints(min_length=1, max_length=120)]
DefaultText = Annotated[str, StringConstraints(min_length=1, max_length=500)]
Line200 = Annotated[str, StringConstraints(max_length=200)]
Excerpt = Annotated[str, StringConstraints(max_length=300)]


class QuestionKind(StrEnum):
    """How a question is asked (ARCHITECTURE §8.2)."""

    SINGLE = "single"
    MULTI = "multi"
    TEXT = "text"
    CONFIRM = "confirm"


CONFIRM_VALUES = ("yes", "no")


class ProposedQuestion(StrictModel):
    """A question the interviewer wants to ask."""

    id: QuestionId
    dimension: Dimension
    kind: QuestionKind
    question: QuestionText
    options: list[OptionText] = Field(max_length=8)
    default: list[DefaultText] = Field(max_length=8)
    why: Line200
    blocking: bool

    @model_validator(mode="after")
    def _consistent(self) -> Self:
        choices = self.kind in (QuestionKind.SINGLE, QuestionKind.MULTI)
        if choices and len(self.options) < 2:
            raise ValueError(f"a {self.kind.value} question needs at least two options")
        if not choices and self.options:
            raise ValueError(f"a {self.kind.value} question has no options")
        if len(set(self.options)) != len(self.options):
            raise ValueError("options must be unique")
        if self.kind is not QuestionKind.MULTI and len(self.default) > 1:
            raise ValueError(f"a {self.kind.value} question has at most one default")
        if choices and any(d not in self.options for d in self.default):
            raise ValueError("every default must be one of the options")
        if self.kind is QuestionKind.CONFIRM and any(d not in CONFIRM_VALUES for d in self.default):
            raise ValueError("a confirm default is yes or no")
        return self


class Extracted(StrictModel):
    """An answer the idea file already gives."""

    dimension: Dimension
    question: QuestionText
    answer: AnswerText


class ProposedCoverage(StrictModel):
    """The interviewer's status for each checklist dimension."""

    problem_goals: ProposedStatus
    users_personas: ProposedStatus
    core_features: ProposedStatus
    data: ProposedStatus
    integrations: ProposedStatus
    scale_performance: ProposedStatus
    security_compliance: ProposedStatus
    deployment_ops: ProposedStatus
    constraints: ProposedStatus
    success_metrics: ProposedStatus

    def as_map(self) -> dict[Dimension, ProposedStatus]:
        """The proposals keyed by dimension."""
        return {dim: getattr(self, dim.value) for dim in Dimension}


class InterviewRound(StrictModel):
    """The interviewer's output (ARCHITECTURE §14.1)."""

    one_liner: Line200
    extracted: list[Extracted] = Field(max_length=30)
    questions: list[ProposedQuestion] = Field(max_length=5)
    coverage: ProposedCoverage
    injection_suspected: list[Excerpt] = Field(max_length=10)

    @model_validator(mode="after")
    def _unique_ids(self) -> Self:
        ids = [q.id for q in self.questions]
        if len(set(ids)) != len(ids):
            raise ValueError("question ids must be unique")
        return self


@dataclass(frozen=True, slots=True)
class InterviewerInput:
    """What the interviewer sees. Every text aipm did not write is `Untrusted`."""

    project: str
    round: int
    extract: bool
    questions_per_round: int
    scores: dict[Dimension, float]
    requirements: Untrusted
    used_ids: frozenset[str]
    idea: Untrusted | None = None
    repo_map: Untrusted | None = None


class Interviewer:
    """The interviewer role."""

    name: ClassVar[RoleName] = RoleName.INTERVIEWER
    template_version: ClassVar[str] = TEMPLATE_VERSION
    output_schema: ClassVar[type[InterviewRound]] = InterviewRound

    def __init__(self, *, nonce: NonceFactory | None = None) -> None:
        self._nonce = nonce

    def render(self, inp: InterviewerInput) -> RenderedPrompt:
        """Render the system prompt and the round's user content."""
        dimensions = [
            {
                "name": dim.value,
                "weight": WEIGHTS[dim],
                "score": f"{inp.scores.get(dim, 0.0):.2f}",
                "needs": NEEDS[dim],
            }
            for dim in Dimension
        ]
        context: dict[str, object] = {
            "project": inp.project,
            "round": inp.round,
            "extract": inp.extract,
            "questions_per_round": inp.questions_per_round,
            "next_question_id": next_id("question", inp.used_ids),
            "dimensions": dimensions,
            "requirements": inp.requirements,
            "idea": inp.idea,
            "repo_map": inp.repo_map,
        }
        return render_prompt(self.name, context, nonce=self._nonce)

    def postprocess(self, out: InterviewRound, inp: InterviewerInput) -> InterviewRound:
        """Drop extractions unless asked for, cap the questions and number them sequentially.

        The model's own IDs are only format-checked: aipm numbers every new question after the
        highest ID already used, so a model can neither reuse an ID nor exhaust the ID space.
        """
        used = set(inp.used_ids)
        extracted = out.extracted if inp.extract else []
        for _ in extracted:  # extracted answers take the first IDs (see extraction_ids)
            used.add(next_id("question", used))
        questions: list[ProposedQuestion] = []
        for question in out.questions[: inp.questions_per_round]:
            qid = next_id("question", used)
            used.add(qid)
            questions.append(question.model_copy(update={"id": qid}))
        return out.model_copy(update={"questions": questions, "extracted": extracted})


def extraction_ids(out: InterviewRound, used_ids: frozenset[str]) -> list[str]:
    """The IDs `postprocess` reserved for the extracted answers, in order."""
    used = set(used_ids)
    ids: list[str] = []
    for _ in out.extracted:
        ids.append(next_id("question", used))
        used.add(ids[-1])
    return ids


def create(*, nonce: NonceFactory | None = None) -> Interviewer:
    """Return the role."""
    return Interviewer(nonce=nonce)
