"""The state snapshot that phase derivation reads (ARCHITECTURE §7.1).

The application layer builds it by loading every `.pm/` file once; `derive_phase` is a pure
function of it. `hashes` holds the normalized sha256 of each file that exists, and of the ADR
directory listing under `ArtifactKind.ADR`.
"""

from collections.abc import Mapping
from dataclasses import dataclass, field

from aipm.domain.models.artifacts import (
    ApprovalsDoc,
    ArchitectureDoc,
    PrdDoc,
    RequirementsDoc,
    TasksDoc,
    ThreatModelDoc,
)
from aipm.domain.models.base import ArtifactKind


@dataclass(frozen=True, slots=True)
class StateSnapshot:
    """Everything phase derivation needs, read once."""

    initialized: bool = False
    hashes: Mapping[ArtifactKind, str] = field(default_factory=dict[ArtifactKind, str])
    requirements: RequirementsDoc | None = None
    prd: PrdDoc | None = None
    architecture: ArchitectureDoc | None = None
    threat_model: ThreatModelDoc | None = None
    tasks: TasksDoc | None = None
    approvals: ApprovalsDoc = field(default_factory=ApprovalsDoc)
    coverage_threshold: float = 0.85
    trusted: bool = False
