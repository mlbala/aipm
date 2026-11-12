"""The ToolAdapter protocol (ARCHITECTURE §5.3, §11)."""

from dataclasses import dataclass, field
from pathlib import Path
from typing import Protocol

from aipm.domain.models import GeneratedFile, ProjectContext, TaskSpec, ToolName, Workspace
from aipm.execution.process import ProcessResult


@dataclass(frozen=True, slots=True)
class Capabilities:
    """What `<tool> --version` showed and, for dispatch, which flags `<tool> --help` lists.

    `flags_checked` is set once `--help` was read; `missing` names every required flag or
    choice it did not list. Dispatch needs `dispatchable` (ARCHITECTURE §11).
    """

    tool: ToolName
    found: bool
    path: str | None = None
    version: str | None = None
    flags_checked: bool = False
    missing: tuple[str, ...] = ()
    launcher: tuple[str, ...] = ()
    """How to start the tool: its interpreter (resolved outside the repository), then the tool;
    or just the tool."""

    @property
    def dispatchable(self) -> bool:
        """Found, with a readable version, and every required flag present."""
        return self.found and self.version is not None and self.flags_checked and not self.missing


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
    """What one attempt may do and spend.

    `allowed_commands` holds, for each command gate the task uses, its argv as the agent sees it
    up to the first placeholder (`GateCommand.allow_prefix`); the agent may run those and
    nothing else through its shell tool.
    """

    timeout_s: float
    task_usd: float
    allowed_commands: tuple[tuple[str, ...], ...] = ()
    pass_env: tuple[str, ...] = ()
    allow_auto_mode: bool = False
    bare: bool = True


@dataclass(frozen=True, slots=True)
class Invocation:
    """How to start one agent: argv (fixed fragments and validated values only), the prompt
    for stdin, the environment, the files to write first (absolute path, text), the API
    domains the agent's network profile allows, and the agent's own programs (its executable
    and interpreter), which its sandbox must let it read."""

    argv: tuple[str, ...]
    stdin: bytes
    env: dict[str, str]
    files: tuple[tuple[Path, str], ...] = ()
    api_domains: tuple[str, ...] = ()
    programs: tuple[str, ...] = ()


@dataclass(frozen=True, slots=True)
class AgentResult:
    """What aipm takes from an agent's output. Self-reports carry no authority (SECURITY.md
    §7.8): only `blocked_question` can change a task, and only to `blocked`."""

    exit_code: int | None
    timed_out: bool
    saw_result: bool = False
    is_error: bool = False
    subtype: str | None = None
    cost_usd: float | None = None
    session_id: str | None = None
    blocked_question: str | None = None


class ToolAdapter(Protocol):
    """Render prompts for, and dispatch, one coding tool."""

    name: ToolName
    required_env: tuple[str, ...]
    api_domains: tuple[str, ...]

    def detect(self, *, flags: bool = False, repo: Path | None = None) -> Capabilities:
        """Return the version and, with `flags`, the safety flags present (cached per version).

        With `repo`, the tool is looked up on PATH outside the repository only.
        """
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

    def preview_argv(self, limits: DispatchLimits, ws: Workspace) -> tuple[str, ...]:
        """The argv `build_invocation` would use, for `--dry-run`."""
        ...

    def parse_result(self, out: ProcessResult) -> AgentResult:
        """Parse the agent's output; self-reports carry no authority."""
        ...
