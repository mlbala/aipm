"""Schemas for `.pm/` artifacts and the data passed between components (ARCHITECTURE §6.3).

Placeholders: build prompt 02 replaces them with Pydantic v2 models that use
`extra="forbid"`, length limits, ID regexes and enums.
"""

from dataclasses import dataclass
from enum import StrEnum
from typing import NewType


class ArtifactKind(StrEnum):
    """The kinds of `.pm/` artifact (ARCHITECTURE §6.1)."""

    CONFIG = "config"
    REQUIREMENTS = "requirements"
    PRD = "prd"
    ARCHITECTURE = "architecture"
    ADR = "adr"
    THREAT_MODEL = "threat_model"
    TASKS = "tasks"
    WORKSHEET = "worksheet"
    APPROVALS = "approvals"
    REPO_MAP = "repo_map"


class Phase(StrEnum):
    """Project phases (ARCHITECTURE §7.1)."""

    UNINITIALIZED = "uninitialized"
    INITIALIZED = "initialized"
    DISCOVERING = "discovering"
    REQUIREMENTS_READY = "requirements_ready"
    PRD_DRAFT = "prd_draft"
    PRD_APPROVED = "prd_approved"
    DESIGN_DRAFT = "design_draft"
    DESIGN_APPROVED = "design_approved"
    PLAN_DRAFT = "plan_draft"
    PLAN_APPROVED = "plan_approved"
    BUILDING = "building"
    BUILT = "built"


class RoleName(StrEnum):
    """LLM roles (ARCHITECTURE §14.1)."""

    INTERVIEWER = "interviewer"
    PRD_WRITER = "prd_writer"
    ARCHITECT = "architect"
    THREAT_MODELER = "threat_modeler"
    PLANNER = "planner"
    AC_REVIEWER = "ac_reviewer"


class ToolName(StrEnum):
    """Coding tools with an adapter (ARCHITECTURE §11)."""

    CLAUDE = "claude"
    CODEX = "codex"
    COPILOT = "copilot"
    GEMINI = "gemini"


RepoId = NewType("RepoId", str)
"""First 16 hex characters of sha256(realpath(repo_root)) (ARCHITECTURE §6.1)."""


@dataclass(frozen=True, slots=True)
class Artifact:
    """Placeholder for a loaded `.pm/` artifact (build prompt 02)."""


@dataclass(frozen=True, slots=True)
class StateSnapshot:
    """Placeholder for the hashes and approvals that phase derivation reads (prompt 04)."""


@dataclass(frozen=True, slots=True)
class Task:
    """Placeholder for a task in `tasks.yaml` (build prompt 02)."""


@dataclass(frozen=True, slots=True)
class TaskSpec:
    """Placeholder for the canonical task spec given to adapters (ARCHITECTURE §10.1)."""


@dataclass(frozen=True, slots=True)
class GateDef:
    """Placeholder for one gate from the trusted menu (ARCHITECTURE §13.1)."""


@dataclass(frozen=True, slots=True)
class GateReport:
    """Placeholder for the result of a gate run (ARCHITECTURE §13.2)."""


@dataclass(frozen=True, slots=True)
class Workspace:
    """Placeholder for a worktree or working tree that gates and agents run in."""


@dataclass(frozen=True, slots=True)
class ChangeSet:
    """Placeholder for the diff facts that post-change checks inspect (prompt 06)."""


@dataclass(frozen=True, slots=True)
class ProjectContext:
    """Placeholder for the approved facts that context files are rendered from."""


@dataclass(frozen=True, slots=True)
class GeneratedFile:
    """Placeholder for a context file aipm will write (ARCHITECTURE §10.2)."""
