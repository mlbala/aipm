"""The ToolAdapter protocol (ARCHITECTURE §5.3, §11)."""

from dataclasses import dataclass, field
from typing import Protocol

from aipm.domain.models import GeneratedFile, ProjectContext, TaskSpec, ToolName, Workspace
from aipm.execution.process import ProcessResult


@dataclass(frozen=True, slots=True)
class Capabilities:
    """What `<tool> --version` showed. Flag checks from `--help` arrive with dispatch (v0.3)."""

    tool: ToolName
    found: bool
    path: str | None = None
    version: str | None = None


@dataclass(frozen=True, slots=True)
class RenderedTaskPrompt:
    """A tool-specific task prompt, within the size budget (ARCHITECTURE §10.1)."""

    tool: ToolName
    task_id: str
    text: str
    omitted: tuple[str, ...] = field(default_factory=tuple[str, ...])

    @property
    def size(self) -> int:
        """The prompt's size in UTF-8 bytes."""
        return len(self.text.encode("utf-8"))


@dataclass(frozen=True, slots=True)
class DispatchLimits:
    """Timeout and budget for one attempt (placeholder, prompt 07)."""


@dataclass(frozen=True, slots=True)
class Invocation:
    """argv, stdin, environment, files and sandbox profile (placeholder, prompt 07)."""


@dataclass(frozen=True, slots=True)
class AgentResult:
    """Cost, session id and blocker line parsed from agent output (placeholder, prompt 07)."""


class ToolAdapter(Protocol):
    """Render prompts for, and later dispatch, one coding tool."""

    name: ToolName

    def detect(self) -> Capabilities:
        """Return the version and safety flags present (cached per version)."""
        ...

    def context_files(self, ctx: ProjectContext) -> list[GeneratedFile]:
        """Return the tool's context files."""
        ...

    def render_prompt(self, task: TaskSpec, ctx: ProjectContext) -> RenderedTaskPrompt:
        """Render the task prompt."""
        ...

    def build_invocation(
        self, p: RenderedTaskPrompt, limits: DispatchLimits, ws: Workspace
    ) -> Invocation:
        """Build the argv from fixed fragments plus validated values."""
        ...

    def parse_result(self, out: ProcessResult) -> AgentResult:
        """Parse the agent's output; self-reports carry no authority."""
        ...
