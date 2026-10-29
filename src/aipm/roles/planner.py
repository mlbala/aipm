"""Planner: the task graph (ARCHITECTURE §9, §14.1).

Input: the PRD, the architecture and the threat model, each wrapped as `Untrusted` with a label
such as `approved:prd` (§14.1), plus, from trusted code and config, the gate menu by name only
(never its argv, P-12), the IDs that must be traced, and the protected paths. The project's own
settings (test roots, serialized paths, extra protected paths) come from `.pm/config.yaml`, so
they are wrapped too.

Output: proposed tasks. They are bounded shapes only; `aipm.domain.dag.validate_plan` applies
every rule and turns them into `Task`s, whatever the prompt said.
"""

from dataclasses import dataclass
from typing import Annotated, ClassVar

from pydantic import Field, StringConstraints

from aipm.domain.models import ProposedTask, RoleName, StrictModel
from aipm.domain.models.plan import MAX_PROPOSED_TASKS
from aipm.llm.gateway import RenderedPrompt
from aipm.roles.base import render_prompt
from aipm.security.paths import PROTECTED_PATHS
from aipm.security.untrusted import NonceFactory, Untrusted

TEMPLATE_VERSION = "1"

Excerpt = Annotated[str, StringConstraints(max_length=300)]


class PlanDraft(StrictModel):
    """The planner's output."""

    tasks: list[ProposedTask] = Field(max_length=MAX_PROPOSED_TASKS)
    injection_suspected: list[Excerpt] = Field(max_length=10)


@dataclass(frozen=True, slots=True)
class MenuGate:
    """A gate the planner may name; its command stays out of the prompt."""

    name: str
    required: bool


@dataclass(frozen=True, slots=True)
class PlannerInput:
    """The upstream artifacts as untrusted text, and the menu and IDs from trusted code."""

    project: str
    prd: Untrusted
    architecture: Untrusted
    threat_model: Untrusted
    gates: tuple[MenuGate, ...]
    must_features: tuple[str, ...]
    threats_to_trace: tuple[str, ...]
    settings: Untrusted
    max_tasks: int
    problems: Untrusted | None = None


class Planner:
    """The planner role."""

    name: ClassVar[RoleName] = RoleName.PLANNER
    template_version: ClassVar[str] = TEMPLATE_VERSION
    output_schema: ClassVar[type[PlanDraft]] = PlanDraft

    def __init__(self, *, nonce: NonceFactory | None = None) -> None:
        self._nonce = nonce

    def render(self, inp: PlannerInput) -> RenderedPrompt:
        """Render the system prompt, the artifacts, the gate names and any repair problems."""
        context: dict[str, object] = {
            "project": inp.project,
            "prd": inp.prd,
            "architecture": inp.architecture,
            "threat_model": inp.threat_model,
            "gates": [{"name": g.name, "required": g.required} for g in inp.gates],
            "must_features": list(inp.must_features),
            "threats_to_trace": list(inp.threats_to_trace),
            "protected": list(PROTECTED_PATHS),
            "settings": inp.settings,
            "max_tasks": inp.max_tasks,
            "problems": inp.problems,
        }
        return render_prompt(self.name, context, nonce=self._nonce)

    def postprocess(self, out: PlanDraft, inp: PlannerInput) -> PlanDraft:
        """Nothing here: the plan validator applies every rule (`aipm.domain.dag`)."""
        del inp
        return out


def create(*, nonce: NonceFactory | None = None) -> Planner:
    """Return the role."""
    return Planner(nonce=nonce)
