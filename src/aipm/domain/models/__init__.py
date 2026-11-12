"""Schemas for `.pm/` artifacts and the data passed between components (ARCHITECTURE §6.3).

Pydantic v2 models with `extra="forbid"`, length limits, ID regexes and enums, plus the frozen
dataclasses of `changes`, which aipm builds itself and never parses from text.
"""

from dataclasses import dataclass
from pathlib import Path
from typing import Any

from aipm.domain.models.artifacts import (
    APPROVED_NAMES,
    AcceptanceCriterion,
    AcOverride,
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
    TaskChange,
    TaskChangeAction,
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
from aipm.domain.models.changes import (
    GITLINK_MODE,
    SYMLINK_MODE,
    ChangeSet,
    ChangeStatus,
    FileChange,
    GateWorkspace,
)
from aipm.domain.models.events import (
    JournalEvent,
    JournalEventType,
    SecurityEvent,
    SecurityEventKind,
)
from aipm.domain.models.gates import (
    BuiltinGate,
    GateDef,
    GateFinding,
    GateReport,
    GateResult,
    GateStatus,
    NetworkProfile,
    PrepareDef,
)
from aipm.domain.models.plan import ProposedDependency, ProposedTask
from aipm.domain.models.prompts import (
    ComponentInfo,
    FeatureInfo,
    GateCommand,
    GateFailure,
    GeneratedFile,
    ProjectContext,
    TaskSpec,
    UpstreamTask,
)
from aipm.domain.models.snapshot import StateSnapshot

type Artifact = YamlArtifact | MarkdownArtifact[Any]
"""Any artifact the state store can load and save."""

__all__ = [
    "ADR_DIR",
    "APPROVED_NAMES",
    "ARTIFACT_FILES",
    "GITLINK_MODE",
    "SCHEMA_VERSION",
    "SYMLINK_MODE",
    "AcOverride",
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
    "ChangeStatus",
    "Component",
    "ComponentInfo",
    "Coverage",
    "DependencyAdd",
    "Dimension",
    "Done",
    "Ecosystem",
    "Feature",
    "FeatureInfo",
    "FileChange",
    "FrontMatter",
    "GateCommand",
    "GateDef",
    "GateFailure",
    "GateFinding",
    "GateReport",
    "GateResult",
    "GateStatus",
    "GateWorkspace",
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
    "TaskChange",
    "TaskChangeAction",
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
    "UpstreamTask",
    "Workspace",
    "YamlArtifact",
]


@dataclass(frozen=True, slots=True)
class Workspace:
    """Where one dispatch runs (ARCHITECTURE §12.4).

    - `root`: the task's worktree, outside the repository; the agent's working directory.
    - `temp_dir`: the agent's private temp dir for this attempt (writable by the agent).
    - `context_dir`: a per-attempt directory the agent may read but not write, for the context
      file passed with the prompt (ADR-0023).
    - `config_home`: the agent's isolated configuration home for the run.
    - `context_text`: the project context given alongside the prompt (the `AGENTS.md` block).
    - `resume_session`: the session a fix attempt continues; the adapter validates it.
    """

    root: Path
    temp_dir: Path
    context_dir: Path
    config_home: Path
    context_text: str = ""
    resume_session: str | None = None
