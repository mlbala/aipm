"""The ToolAdapter protocol (ARCHITECTURE §5.3, §11)."""

from dataclasses import dataclass
from typing import Protocol

from aipm.domain.models import GeneratedFile, ProjectContext, TaskSpec, ToolName, Workspace
from aipm.execution.process import ProcessResult


@dataclass(frozen=True, slots=True)
class Capabilities:
    """Detected tool version and flags (placeholder, prompt 05)."""


@dataclass(frozen=True, slots=True)
class RenderedTaskPrompt:
    """A tool-specific task prompt (placeholder, prompt 05)."""


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
