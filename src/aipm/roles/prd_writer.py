"""PRD writer (ARCHITECTURE §14.1).

Input: `requirements.yaml`, passed as `Untrusted` like every artifact (§14.1). Output: the PRD
sections, features and non-functional requirements. `build_prd` turns the validated output into
`prd.md` deterministically: the front matter comes from the validated lists, the body uses the
fixed headings of §6.3, and the Assumptions and Open questions sections come from
`requirements.yaml`, never from the model. The result is T2 until a human approves it (G1).
"""

from dataclasses import dataclass
from typing import Annotated, ClassVar, Self

from pydantic import Field, StringConstraints, model_validator

from aipm.domain.models import (
    Feature,
    NonFunctional,
    PrdDerivedFrom,
    PrdDoc,
    PrdFrontMatter,
    Priority,
    RequirementsDoc,
    RoleName,
    StrictModel,
)
from aipm.domain.models.base import FeatureId, NfrId, Str120, Token
from aipm.llm.gateway import RenderedPrompt
from aipm.roles.base import render_prompt
from aipm.security.untrusted import NonceFactory, Untrusted

TEMPLATE_VERSION = "1"

Section = Annotated[str, StringConstraints(max_length=4000)]
Description = Annotated[str, StringConstraints(max_length=1000)]
Statement = Annotated[str, StringConstraints(min_length=1, max_length=500)]
Excerpt = Annotated[str, StringConstraints(max_length=300)]


class DraftFeature(StrictModel):
    """A feature with the description that goes into the PRD body."""

    id: FeatureId
    title: Str120
    priority: Priority
    description: Description


class DraftNfr(StrictModel):
    """A non-functional requirement."""

    id: NfrId
    category: Token
    statement: Statement


class PrdDraft(StrictModel):
    """The PRD writer's output."""

    problem: Section
    users: Section
    goals_and_metrics: Section
    scope: Section
    out_of_scope: Section
    features: list[DraftFeature] = Field(max_length=60)
    non_functional: list[DraftNfr] = Field(max_length=40)
    injection_suspected: list[Excerpt] = Field(max_length=10)

    @model_validator(mode="after")
    def _unique_ids(self) -> Self:
        for ids, what in (
            ([f.id for f in self.features], "feature"),
            ([n.id for n in self.non_functional], "requirement"),
        ):
            if len(set(ids)) != len(ids):
                raise ValueError(f"{what} ids must be unique")
        return self


@dataclass(frozen=True, slots=True)
class PrdWriterInput:
    """The requirements, as untrusted text, and the project name."""

    project: str
    requirements: Untrusted


class PrdWriter:
    """The PRD writer role."""

    name: ClassVar[RoleName] = RoleName.PRD_WRITER
    template_version: ClassVar[str] = TEMPLATE_VERSION
    output_schema: ClassVar[type[PrdDraft]] = PrdDraft

    def __init__(self, *, nonce: NonceFactory | None = None) -> None:
        self._nonce = nonce

    def render(self, inp: PrdWriterInput) -> RenderedPrompt:
        """Render the system prompt and the requirements."""
        context: dict[str, object] = {"project": inp.project, "requirements": inp.requirements}
        return render_prompt(self.name, context, nonce=self._nonce)

    def postprocess(self, out: PrdDraft, inp: PrdWriterInput) -> PrdDraft:
        """Nothing to change: the schema already holds every rule."""
        del inp
        return out


def create(*, nonce: NonceFactory | None = None) -> PrdWriter:
    """Return the role."""
    return PrdWriter(nonce=nonce)


# ---------------------------------------------------------------- prd.md


def _indent(text: str) -> str:
    return "\n".join(f"  {line}" if line else "" for line in text.strip().splitlines())


def _section(title: str, text: str) -> str:
    body = text.strip() or "_Not specified._"
    return f"## {title}\n\n{body}\n"


def _features(draft: PrdDraft) -> str:
    if not draft.features:
        return "_None._"
    lines: list[str] = []
    for f in draft.features:
        lines.append(f"- **{f.id}** ({f.priority.value}): {f.title}")
        if f.description.strip():
            lines.append(_indent(f.description))
    return "\n".join(lines)


def _nfrs(draft: PrdDraft) -> str:
    if not draft.non_functional:
        return "_None._"
    return "\n".join(f"- **{n.id}** ({n.category}): {n.statement}" for n in draft.non_functional)


def _assumptions(doc: RequirementsDoc) -> str:
    if not doc.assumptions:
        return "_None._"
    return "\n".join(
        f"- **{a.id}** ({a.dimension.value}, {'confirmed' if a.confirmed else 'unconfirmed'}): "
        f"{a.statement}"
        for a in doc.assumptions
    )


def _open_questions(doc: RequirementsDoc) -> str:
    if not doc.open_questions:
        return "_None._"
    return "\n".join(
        f"- **{q.id}** ({q.dimension.value}{', blocking' if q.blocking else ''}): {q.question}"
        for q in doc.open_questions
    )


def build_prd(draft: PrdDraft, doc: RequirementsDoc, *, requirements_sha: str) -> PrdDoc:
    """The `prd.md` artifact: validated front matter plus a body with the fixed headings."""
    meta = PrdFrontMatter(
        derived_from=PrdDerivedFrom(requirements=requirements_sha),
        features=[Feature(id=f.id, title=f.title, priority=f.priority) for f in draft.features],
        non_functional=[
            NonFunctional(id=n.id, category=n.category, statement=n.statement)
            for n in draft.non_functional
        ],
    )
    title = f"# PRD: {doc.project.name}\n"
    intro = f"\n{doc.project.one_liner}\n" if doc.project.one_liner else ""
    parts = [
        title + intro,
        _section("Problem", draft.problem),
        _section("Users", draft.users),
        _section("Goals and metrics", draft.goals_and_metrics),
        _section("Scope", draft.scope),
        _section("Features", _features(draft)),
        _section("Non-functional requirements", _nfrs(draft)),
        _section("Out of scope", draft.out_of_scope),
        _section("Assumptions", _assumptions(doc)),
        _section("Open questions", _open_questions(doc)),
    ]
    return PrdDoc(meta=meta, body="\n".join(parts))
