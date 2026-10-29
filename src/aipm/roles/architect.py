"""Architect: the architecture and its ADRs (ARCHITECTURE §14.1).

Input: the PRD (wrapped as `Untrusted` with a label such as `approved:prd`, §14.1), the repo map
for a brownfield project, and the names of the built-in stack templates (T0). Output: the stack,
one built-in `stack_template`, the components, `is_llm_app`, a few fixed sections and the ADRs.

`problems` checks what the schema cannot: the template must be built in (SECURITY.md §7.4) and
every component path must pass `safe_rel_glob`. `build_architecture` and `build_adrs` write the
files in code: aipm sets the IDs, the front matter and the fixed headings. The result is T2
until G2.
"""

from collections.abc import Sequence
from dataclasses import dataclass
from typing import Annotated, ClassVar, Self

from pydantic import Field, StringConstraints, model_validator

from aipm.domain.errors import PolicyViolation
from aipm.domain.models import (
    AdrDoc,
    AdrFrontMatter,
    ArchitectureDerivedFrom,
    ArchitectureDoc,
    ArchitectureFrontMatter,
    Component,
    RoleName,
    Stack,
    StrictModel,
)
from aipm.domain.models.base import ComponentId, Str40, Str120, Str300
from aipm.llm.gateway import RenderedPrompt
from aipm.roles.base import render_prompt
from aipm.security.paths import safe_rel_glob
from aipm.security.untrusted import NonceFactory, Untrusted

TEMPLATE_VERSION = "1"
MAX_ADRS = 20

Section = Annotated[str, StringConstraints(max_length=4000)]
Excerpt = Annotated[str, StringConstraints(max_length=300)]
GlobText = Annotated[str, StringConstraints(max_length=512)]
TemplateText = Annotated[str, StringConstraints(max_length=40)]


class DraftComponent(StrictModel):
    """A component; its paths are checked by `problems`, not by the schema."""

    id: ComponentId
    name: Str40
    paths: list[GlobText] = Field(max_length=20)
    responsibility: Str300


class DraftAdr(StrictModel):
    """One decision. aipm numbers it and builds its file name."""

    title: Str120
    context: Section
    decision: Section
    consequences: Section


class ArchitectureDraft(StrictModel):
    """The architect's output."""

    stack: Stack
    stack_template: TemplateText
    components: list[DraftComponent] = Field(max_length=40)
    is_llm_app: bool
    overview: Section
    data: Section
    interfaces: Section
    deployment: Section
    security: Section
    adrs: list[DraftAdr] = Field(max_length=MAX_ADRS)
    injection_suspected: list[Excerpt] = Field(max_length=10)

    @model_validator(mode="after")
    def _unique_ids(self) -> Self:
        ids = [c.id for c in self.components]
        if len(set(ids)) != len(ids):
            raise ValueError("component ids must be unique")
        return self


@dataclass(frozen=True, slots=True)
class ArchitectInput:
    """The PRD and repo map as untrusted text; the project name and template names are T0."""

    project: str
    mode: str
    prd: Untrusted
    stacks: tuple[str, ...]
    repo_map: Untrusted | None = None
    problems: Untrusted | None = None


class Architect:
    """The architect role."""

    name: ClassVar[RoleName] = RoleName.ARCHITECT
    template_version: ClassVar[str] = TEMPLATE_VERSION
    output_schema: ClassVar[type[ArchitectureDraft]] = ArchitectureDraft

    def __init__(self, *, nonce: NonceFactory | None = None) -> None:
        self._nonce = nonce

    def render(self, inp: ArchitectInput) -> RenderedPrompt:
        """Render the system prompt, the PRD, the repo map and any repair problems."""
        context: dict[str, object] = {
            "project": inp.project,
            "mode": inp.mode,
            "prd": inp.prd,
            "stacks": list(inp.stacks),
            "repo_map": inp.repo_map,
            "problems": inp.problems,
        }
        return render_prompt(self.name, context, nonce=self._nonce)

    def postprocess(self, out: ArchitectureDraft, inp: ArchitectInput) -> ArchitectureDraft:
        """Normalize component paths; `problems` has already rejected unsafe ones."""
        del inp
        components = [c.model_copy(update={"paths": _safe_paths(c.paths)}) for c in out.components]
        return out.model_copy(update={"components": components})


def _safe_paths(paths: Sequence[str]) -> list[str]:
    out: list[str] = []
    for path in paths:
        try:
            glob = safe_rel_glob(path)
        except PolicyViolation:
            continue
        if glob not in out:
            out.append(glob)
    return out


def problems(out: ArchitectureDraft, stacks: Sequence[str]) -> list[str]:
    """What the schema cannot check, in aipm's words only (never the model's text)."""
    found: list[str] = []
    if out.stack_template not in stacks:
        found.append(f"stack_template: must be one of the built-in templates ({', '.join(stacks)})")
    for i, component in enumerate(out.components):
        for k, path in enumerate(component.paths):
            try:
                safe_rel_glob(path)
            except PolicyViolation:
                found.append(
                    f"components.{i}.paths.{k}: not a safe repository-relative glob (no absolute "
                    "path, '..', leading '-', protected path or .pm/)"
                )
    return found


def create(*, nonce: NonceFactory | None = None) -> Architect:
    """Return the role."""
    return Architect(nonce=nonce)


# ---------------------------------------------------------------- architecture.md and adr/


def adr_id(index: int) -> str:
    """aipm's ADR IDs: ADR-0001 for the first decision, and so on."""
    return f"ADR-{index + 1:04d}"


def _section(title: str, text: str) -> str:
    body = text.strip() or "_Not specified._"
    return f"## {title}\n\n{body}\n"


def _stack_text(stack: Stack, template: str) -> str:
    parts = [f"- {name.replace('_', ' ')}: {value}"
             for name, value in stack.model_dump().items() if value]  # fmt: skip
    parts.append(f"- stack template: {template}")
    return "\n".join(parts)


def _components_text(out: ArchitectureDraft) -> str:
    if not out.components:
        return "_None._"
    lines: list[str] = []
    for c in out.components:
        paths = ", ".join(f"`{p}`" for p in c.paths) or "no paths"
        lines.append(f"- **{c.id} {c.name}** ({paths}): {c.responsibility}")
    return "\n".join(lines)


def _decisions_text(out: ArchitectureDraft) -> str:
    if not out.adrs:
        return "_None._"
    return "\n".join(f"- {adr_id(i)}: {a.title}" for i, a in enumerate(out.adrs))


def build_architecture(out: ArchitectureDraft, *, project: str, prd_sha: str) -> ArchitectureDoc:
    """`architecture.md`: validated front matter, then fixed headings."""
    meta = ArchitectureFrontMatter(
        derived_from=ArchitectureDerivedFrom(prd=prd_sha),
        stack=out.stack,
        stack_template=out.stack_template,
        components=[
            Component(id=c.id, name=c.name, paths=c.paths, responsibility=c.responsibility)
            for c in out.components
        ],
        is_llm_app=out.is_llm_app,
        decisions=[adr_id(i) for i in range(len(out.adrs))],
    )
    parts = [
        f"# Architecture: {project}\n",
        _section("Overview", out.overview),
        _section("Stack", _stack_text(out.stack, out.stack_template)),
        _section("Components", _components_text(out)),
        _section("Data", out.data),
        _section("Interfaces", out.interfaces),
        _section("Deployment", out.deployment),
        _section("Security", out.security),
        _section("Decisions", _decisions_text(out)),
    ]
    return ArchitectureDoc(meta=meta, body="\n".join(parts))


def build_adrs(out: ArchitectureDraft) -> list[AdrDoc]:
    """One `adr/NNNN-<slug>.md` per decision, numbered by aipm."""
    docs: list[AdrDoc] = []
    for i, a in enumerate(out.adrs):
        meta = AdrFrontMatter(id=adr_id(i), title=a.title)
        body = "\n".join(
            [
                f"# {adr_id(i)}: {a.title}\n",
                _section("Context", a.context),
                _section("Decision", a.decision),
                _section("Consequences", a.consequences),
            ]
        )
        docs.append(AdrDoc(meta=meta, body=body))
    return docs
