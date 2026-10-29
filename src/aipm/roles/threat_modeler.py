"""Threat modeler (ARCHITECTURE §14.1).

Input: the drafted architecture (wrapped as `Untrusted`, `unapproved:architecture` until G2),
the component IDs aipm validated, and, when the architecture says `is_llm_app`, the OWASP Top 10
for LLM Applications from aipm's own code (T0). Output: the threats and a few sections.

`problems` checks what the schema cannot: every threat names a known component, and an LLM app
covers all ten OWASP LLM items, while a non-LLM app uses none. `build_threat_model` writes the
file in code; the threat table and the OWASP mapping come from the validated list.
"""

from collections.abc import Sequence
from dataclasses import dataclass
from typing import Annotated, ClassVar, Self

from pydantic import Field, StringConstraints, model_validator

from aipm.domain.models import (
    RoleName,
    Severity,
    StrictModel,
    Stride,
    Threat,
    ThreatModelDerivedFrom,
    ThreatModelDoc,
    ThreatModelFrontMatter,
)
from aipm.domain.models.base import ComponentId, Str120, Str1000, ThreatId
from aipm.llm.gateway import RenderedPrompt
from aipm.roles.base import render_prompt
from aipm.security.untrusted import NonceFactory, Untrusted

TEMPLATE_VERSION = "1"

OWASP_LLM_TOP_10: tuple[tuple[str, str], ...] = (
    ("LLM01", "Prompt Injection"),
    ("LLM02", "Sensitive Information Disclosure"),
    ("LLM03", "Supply Chain"),
    ("LLM04", "Data and Model Poisoning"),
    ("LLM05", "Improper Output Handling"),
    ("LLM06", "Excessive Agency"),
    ("LLM07", "System Prompt Leakage"),
    ("LLM08", "Vector and Embedding Weaknesses"),
    ("LLM09", "Misinformation"),
    ("LLM10", "Unbounded Consumption"),
)
"""OWASP Top 10 for LLM Applications (2025), as SECURITY.md §13.2 lists it."""

Section = Annotated[str, StringConstraints(max_length=4000)]
Excerpt = Annotated[str, StringConstraints(max_length=300)]
OwaspId = Annotated[str, StringConstraints(pattern=r"^LLM(?:0[1-9]|10)$")]
_SEVERITY_ORDER = {s: i for i, s in enumerate(Severity)}


class DraftThreat(StrictModel):
    """One threat as the model proposes it."""

    id: ThreatId
    stride: Stride
    owasp_llm: OwaspId | None
    component: ComponentId
    title: Str120
    severity: Severity
    mitigation: Str1000


class ThreatModelDraft(StrictModel):
    """The threat modeler's output."""

    threats: list[DraftThreat] = Field(max_length=80)
    summary: Section
    assumptions: Section
    residual_risks: Section
    injection_suspected: list[Excerpt] = Field(max_length=10)

    @model_validator(mode="after")
    def _unique_ids(self) -> Self:
        ids = [t.id for t in self.threats]
        if len(set(ids)) != len(ids):
            raise ValueError("threat ids must be unique")
        return self


@dataclass(frozen=True, slots=True)
class ThreatModelerInput:
    """The drafted architecture as untrusted text; component IDs and the LLM flag are checked."""

    project: str
    architecture: Untrusted
    components: tuple[str, ...]
    is_llm_app: bool
    problems: Untrusted | None = None


class ThreatModeler:
    """The threat modeler role."""

    name: ClassVar[RoleName] = RoleName.THREAT_MODELER
    template_version: ClassVar[str] = TEMPLATE_VERSION
    output_schema: ClassVar[type[ThreatModelDraft]] = ThreatModelDraft

    def __init__(self, *, nonce: NonceFactory | None = None) -> None:
        self._nonce = nonce

    def render(self, inp: ThreatModelerInput) -> RenderedPrompt:
        """Render the system prompt, the architecture and, for an LLM app, the OWASP list."""
        context: dict[str, object] = {
            "project": inp.project,
            "architecture": inp.architecture,
            "components": list(inp.components),
            "is_llm_app": inp.is_llm_app,
            "owasp": [{"id": i, "name": n} for i, n in OWASP_LLM_TOP_10],
            "problems": inp.problems,
        }
        return render_prompt(self.name, context, nonce=self._nonce)

    def postprocess(self, out: ThreatModelDraft, inp: ThreatModelerInput) -> ThreatModelDraft:
        """Order the threats by severity, highest first, then by ID."""
        del inp
        ordered = sorted(out.threats, key=lambda t: (-_SEVERITY_ORDER[t.severity], t.id))
        return out.model_copy(update={"threats": ordered})


def problems(out: ThreatModelDraft, *, components: Sequence[str], is_llm_app: bool) -> list[str]:
    """What the schema cannot check, in aipm's words only."""
    found: list[str] = []
    known = set(components)
    for i, threat in enumerate(out.threats):
        if threat.component not in known:
            listed = ", ".join(components)
            found.append(f"threats.{i}.component: not one of the components ({listed})")
    used = {t.owasp_llm for t in out.threats if t.owasp_llm is not None}
    if is_llm_app:
        missing = [i for i, _ in OWASP_LLM_TOP_10 if i not in used]
        if missing:
            found.append(
                "the architecture is an LLM app, so the threats must cover every OWASP LLM item; "
                f"missing: {', '.join(missing)}"
            )
    elif used:
        found.append("the architecture is not an LLM app, so owasp_llm must be null everywhere")
    return found


def create(*, nonce: NonceFactory | None = None) -> ThreatModeler:
    """Return the role."""
    return ThreatModeler(nonce=nonce)


# ---------------------------------------------------------------- threat-model.md


def _cell(text: str) -> str:
    return " ".join(text.split()).replace("|", "\\|")


def _section(title: str, text: str) -> str:
    body = text.strip() or "_Not specified._"
    return f"## {title}\n\n{body}\n"


def _table(out: ThreatModelDraft) -> str:
    if not out.threats:
        return "_None._"
    rows = [
        "| ID | Severity | STRIDE | Component | Threat | Mitigation |",
        "|---|---|---|---|---|---|",
    ]
    rows.extend(
        f"| {t.id} | {t.severity.value} | {t.stride.value} | {t.component} | {_cell(t.title)} "
        f"| {_cell(t.mitigation)} |"
        for t in out.threats
    )
    return "\n".join(rows)


def _owasp(out: ThreatModelDraft) -> str:
    lines: list[str] = []
    for code, name in OWASP_LLM_TOP_10:
        ids = [t.id for t in out.threats if t.owasp_llm == code]
        lines.append(f"- {code} {name}: {', '.join(ids) or '_none_'}")
    return "\n".join(lines)


def build_threat_model(
    out: ThreatModelDraft, *, project: str, architecture_sha: str, is_llm_app: bool
) -> ThreatModelDoc:
    """`threat-model.md`: the validated threats as front matter, then fixed headings."""
    meta = ThreatModelFrontMatter(
        derived_from=ThreatModelDerivedFrom(architecture=architecture_sha),
        threats=[
            Threat(id=t.id, stride=t.stride, owasp_llm=t.owasp_llm, component=t.component,
                   title=t.title, severity=t.severity, mitigation=t.mitigation)
            for t in out.threats
        ],
    )  # fmt: skip
    parts = [f"# Threat model: {project}\n", _section("Summary", out.summary)]
    parts.append(_section("Threats", _table(out)))
    if is_llm_app:
        parts.append(_section("OWASP Top 10 for LLM Applications", _owasp(out)))
    parts.append(_section("Assumptions", out.assumptions))
    parts.append(_section("Residual risks", out.residual_risks))
    return ThreatModelDoc(meta=meta, body="\n".join(parts))
