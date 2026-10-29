"""Schemas for `.pm/` artifacts and the data passed between components (ARCHITECTURE §6.3).

Pydantic v2 models with `extra="forbid"`, length limits, ID regexes and enums. The placeholders
at the end belong to later build prompts, which replace them.
"""

from dataclasses import dataclass
from typing import Any

from aipm.domain.models.artifacts import (
    APPROVED_NAMES,
    AcceptanceCriterion,
    AdrDoc,
    AdrFrontMatter,
    Answer,
    AnswerSource,
    Approval,
    ApprovalGate,
    ApprovalsDoc,
    ArchitectureDerivedFrom,
    ArchitectureDoc,
    ArchitectureFrontMatter,
    Assumption,
    Blocked,
    BlockedReason,
    Component,
    Coverage,
    DependencyAdd,
    Dimension,
    Done,
    Ecosystem,
    Feature,
    Mode,
    NonFunctional,
    OpenQuestion,
    OverrideReason,
    PrdDerivedFrom,
    PrdDoc,
    PrdFrontMatter,
    Priority,
    ProjectInfo,
    RepoMapDoc,
    RepoMapFrontMatter,
    RequirementsDoc,
    Source,
    SourceKind,
    Stack,
    StaleOverride,
    Stride,
    Task,
    TasksDerivedFrom,
    TasksDoc,
    TaskSize,
    TaskStatus,
    TaskType,
    Threat,
    ThreatModelDerivedFrom,
    ThreatModelDoc,
    ThreatModelFrontMatter,
)
from aipm.domain.models.base import (
    ADR_DIR,
    ARTIFACT_FILES,
    SCHEMA_VERSION,
    ArtifactKind,
    FrontMatter,
    MarkdownArtifact,
    Phase,
    RepoId,
    RoleName,
    Severity,
    StrictModel,
    ToolName,
    YamlArtifact,
)
from aipm.domain.models.events import (
    JournalEvent,
    JournalEventType,
    SecurityEvent,
    SecurityEventKind,
)
from aipm.domain.models.gates import BuiltinGate, GateDef, NetworkProfile, PrepareDef
from aipm.domain.models.plan import ProposedDependency, ProposedTask
from aipm.domain.models.snapshot import StateSnapshot

type Artifact = YamlArtifact | MarkdownArtifact[Any]
"""Any artifact the state store can load and save."""

__all__ = [
    "ADR_DIR",
    "APPROVED_NAMES",
    "ARTIFACT_FILES",
    "SCHEMA_VERSION",
    "AcceptanceCriterion",
    "AdrDoc",
    "AdrFrontMatter",
    "Answer",
    "AnswerSource",
    "Approval",
    "ApprovalGate",
    "ApprovalsDoc",
    "ArchitectureDerivedFrom",
    "ArchitectureDoc",
    "ArchitectureFrontMatter",
    "Artifact",
    "ArtifactKind",
    "Assumption",
    "Blocked",
    "BlockedReason",
    "BuiltinGate",
    "ChangeSet",
    "Component",
    "Coverage",
    "DependencyAdd",
    "Dimension",
    "Done",
    "Ecosystem",
    "Feature",
    "FrontMatter",
    "GateDef",
    "GateReport",
    "GeneratedFile",
    "JournalEvent",
    "JournalEventType",
    "MarkdownArtifact",
    "Mode",
    "NetworkProfile",
    "NonFunctional",
    "OpenQuestion",
    "OverrideReason",
    "Phase",
    "PrdDerivedFrom",
    "PrdDoc",
    "PrdFrontMatter",
    "PrepareDef",
    "Priority",
    "ProjectContext",
    "ProjectInfo",
    "ProposedDependency",
    "ProposedTask",
    "RepoId",
    "RepoMapDoc",
    "RepoMapFrontMatter",
    "RequirementsDoc",
    "RoleName",
    "SecurityEvent",
    "SecurityEventKind",
    "Severity",
    "Source",
    "SourceKind",
    "Stack",
    "StaleOverride",
    "StateSnapshot",
    "StrictModel",
    "Stride",
    "Task",
    "TaskSize",
    "TaskSpec",
    "TaskStatus",
    "TaskType",
    "TasksDerivedFrom",
    "TasksDoc",
    "Threat",
    "ThreatModelDerivedFrom",
    "ThreatModelDoc",
    "ThreatModelFrontMatter",
    "ToolName",
    "Workspace",
    "YamlArtifact",
]


@dataclass(frozen=True, slots=True)
class TaskSpec:
    """Placeholder for the canonical task spec given to adapters (ARCHITECTURE §10.1)."""


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
