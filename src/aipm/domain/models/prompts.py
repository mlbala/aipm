"""What adapters render from (ARCHITECTURE §10): the project context, the task spec and the
context files to write.

All of it is assembled deterministically from approved `.pm/` artifacts and the trusted config;
no LLM is involved. Gate argv here has already passed `compile_gate`. Free text that a model
wrote (titles, descriptions, criteria, names) is carried as plain strings in `ProjectContext`,
which the context generator sanitizes and wraps, and as `Untrusted` in `TaskSpec`, which task
templates can render only through `|untrusted` (SECURITY.md §7.2).
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING

from aipm.domain.models.artifacts import Task

if TYPE_CHECKING:  # the domain models never import Jinja (aipm.security.untrusted does)
    from aipm.security.untrusted import Untrusted


@dataclass(frozen=True, slots=True)
class GateCommand:
    """One gate of the trusted menu as an agent sees it: compiled argv, or a built-in gate."""

    name: str
    required: bool
    argv: tuple[str, ...] | None = None
    builtin: str | None = None


@dataclass(frozen=True, slots=True)
class FeatureInfo:
    """A PRD feature (the title is model text)."""

    id: str
    priority: str
    title: str


@dataclass(frozen=True, slots=True)
class ComponentInfo:
    """An architecture component (the name and responsibility are model text)."""

    id: str
    name: str
    paths: tuple[str, ...]
    responsibility: str


@dataclass(frozen=True, slots=True)
class ProjectContext:
    """The approved facts that context files and task prompts are rendered from."""

    project: str
    mode: str
    one_liner: str
    features: tuple[FeatureInfo, ...]
    stack: tuple[tuple[str, str], ...]
    stack_template: str | None
    components: tuple[ComponentInfo, ...]
    gates: tuple[GateCommand, ...]
    test_roots: tuple[str, ...]
    protected_paths: tuple[str, ...]
    new_dependencies: str
    agent_network: str
    allowed_url_domains: tuple[str, ...] = ()
    tasks: tuple[Task, ...] = ()


@dataclass(frozen=True, slots=True)
class UpstreamTask:
    """A task this task depends on. `title` is None once the size budget trimmed it."""

    id: str
    status: str
    commit: str | None
    title: Untrusted | None


@dataclass(frozen=True, slots=True)
class GateFailure:
    """One failing gate of the previous attempt, its output cut to head and tail."""

    gate: str
    status: str
    output: Untrusted


@dataclass(frozen=True, slots=True)
class TaskSpec:
    """The canonical task spec every adapter renders (ARCHITECTURE §10.1)."""

    id: str
    project: str
    type: str
    size: str
    text: Untrusted
    acceptance_ids: tuple[str, ...]
    owns_files: tuple[str, ...]
    reads_files: tuple[str, ...]
    deps_add: tuple[tuple[str, str], ...]
    upstream: tuple[UpstreamTask, ...]
    verify: tuple[GateCommand, ...]
    builtin_gates: tuple[GateCommand, ...]
    protected_paths: tuple[str, ...]
    new_dependencies: str
    agent_network: str
    previous_attempt: tuple[GateFailure, ...] = ()
    fix: bool = False
    approval: str = "approved"
    """`approved`, or how the plan was not (`stale`, `unapproved`) when run with
    `--accept-stale`; it labels the task text."""
    omitted: tuple[str, ...] = ()
    """What the size budget left out, in the order it was trimmed."""


@dataclass(frozen=True, slots=True)
class GeneratedFile:
    """A context file's managed block (ARCHITECTURE §10.2); the markers are added on write.

    With a `preamble` (YAML front matter), aipm owns the whole file: it is `preamble` followed
    by `block`, with no markers, and any other content is drift (aipm's own subagents and
    skills, SECURITY.md §14.1 I-2).
    """

    path: str
    block: str
    preamble: str | None = None

    @property
    def document(self) -> str:
        """The whole file, for a file aipm owns."""
        return f"{self.preamble or ''}{self.block}"
