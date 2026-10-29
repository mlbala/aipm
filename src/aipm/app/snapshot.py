"""Reading `.pm/` once into a `StateSnapshot` (ARCHITECTURE §6.4, §7.1).

Every artifact is parsed from the same bytes that are hashed. Read-only commands (`status`,
bare `aipm`) do not take the lock: they read everything once, then check every hash again and
read once more if any file changed in between. Trust comes from the user's trust store; a
surface that fails the command policy counts as untrusted.

The snapshot's hash for `tasks.yaml` is the plan hash (`plan_sha256`, ADR-0016): the file's own
hash until a task starts, then the hash of the plan without task progress. G3 approves it.
"""

from dataclasses import dataclass, field
from pathlib import Path

from aipm.app import trust as trust_use_case
from aipm.config.loader import LoadedConfig, load_config
from aipm.domain.errors import PolicyViolation, UsageError
from aipm.domain.models import (
    AdrDoc,
    ApprovalsDoc,
    ArchitectureDoc,
    Artifact,
    ArtifactKind,
    PrdDoc,
    RequirementsDoc,
    StateSnapshot,
    TasksDoc,
    ThreatModelDoc,
)
from aipm.state.layout import pm_root
from aipm.state.store import FileStateStore, plan_sha256

_KINDS = (
    ArtifactKind.REQUIREMENTS,
    ArtifactKind.PRD,
    ArtifactKind.ARCHITECTURE,
    ArtifactKind.THREAT_MODEL,
    ArtifactKind.TASKS,
    ArtifactKind.APPROVALS,
)


@dataclass(frozen=True, slots=True)
class ProjectState:
    """The snapshot plus what commands need next to it."""

    snapshot: StateSnapshot
    adrs: tuple[AdrDoc, ...] = ()
    trust: trust_use_case.TrustReport | None = None
    trust_error: str | None = None
    warnings: tuple[str, ...] = field(default_factory=tuple[str, ...])


@dataclass(slots=True)
class _Read:
    docs: dict[ArtifactKind, Artifact]
    hashes: dict[ArtifactKind, str]
    """File hashes, for the consistent-read check."""
    adrs: list[AdrDoc]

    def snapshot_hashes(self) -> dict[ArtifactKind, str]:
        """The file hashes, with the plan hash (ADR-0016) in place of the `tasks.yaml` one."""
        hashes = dict(self.hashes)
        doc = self.docs.get(ArtifactKind.TASKS)
        if isinstance(doc, TasksDoc):
            hashes[ArtifactKind.TASKS] = plan_sha256(doc, self.hashes[ArtifactKind.TASKS])
        return hashes


def _read_all(store: FileStateStore) -> _Read:
    docs: dict[ArtifactKind, Artifact] = {}
    hashes: dict[ArtifactKind, str] = {}
    for kind in _KINDS:
        if store.exists(kind):
            docs[kind], hashes[kind] = store.load_with_hash(kind)
    adrs, hashes[ArtifactKind.ADR] = store.load_adrs()
    return _Read(docs, hashes, adrs)


def _unchanged(store: FileStateStore, read: _Read) -> bool:
    if any(store.sha256(kind) != read.hashes.get(kind) for kind in _KINDS):
        return False
    return store.adr_sha256() == read.hashes[ArtifactKind.ADR]


def _typed[T](docs: dict[ArtifactKind, Artifact], kind: ArtifactKind, model: type[T]) -> T | None:
    doc = docs.get(kind)
    if doc is None:
        return None
    if not isinstance(doc, model):  # pragma: no cover - the store's mapping
        raise UsageError(f"{kind.value} did not load as expected")
    return doc


def read_snapshot(
    store: FileStateStore, *, coverage_threshold: float, trusted: bool
) -> tuple[StateSnapshot, tuple[AdrDoc, ...]]:
    """Load every artifact once (retrying once if a file changes meanwhile)."""
    if not pm_root(store.repo_root).is_dir():
        return StateSnapshot(), ()
    read = _read_all(store)
    if not _unchanged(store, read):
        read = _read_all(store)
    approvals = _typed(read.docs, ArtifactKind.APPROVALS, ApprovalsDoc) or ApprovalsDoc()
    snapshot = StateSnapshot(
        initialized=True,
        hashes=read.snapshot_hashes(),
        requirements=_typed(read.docs, ArtifactKind.REQUIREMENTS, RequirementsDoc),
        prd=_typed(read.docs, ArtifactKind.PRD, PrdDoc),
        architecture=_typed(read.docs, ArtifactKind.ARCHITECTURE, ArchitectureDoc),
        threat_model=_typed(read.docs, ArtifactKind.THREAT_MODEL, ThreatModelDoc),
        tasks=_typed(read.docs, ArtifactKind.TASKS, TasksDoc),
        approvals=approvals,
        coverage_threshold=coverage_threshold,
        trusted=trusted,
    )
    return snapshot, tuple(read.adrs)


type TrustLookup = tuple[trust_use_case.TrustReport | None, str | None]


def trust_of(root: Path, loaded: LoadedConfig) -> TrustLookup:
    """This user's trust in the repository's execution surface, or why it cannot be trusted."""
    try:
        context = trust_use_case.TrustContext(root=root, loaded=loaded)
        return trust_use_case.inspect(context), None
    except PolicyViolation as exc:
        return None, exc.message


def load_state(store: FileStateStore, *, loaded: LoadedConfig | None = None) -> ProjectState:
    """The snapshot with trust, for phase derivation and status."""
    root = store.repo_root
    if not pm_root(root).is_dir():
        return ProjectState(StateSnapshot())
    cfg = loaded if loaded is not None else load_config(root)
    report, error = trust_of(root, cfg)
    snapshot, adrs = read_snapshot(
        store,
        coverage_threshold=cfg.config.discover.coverage_threshold,
        trusted=report is not None and report.trusted,
    )
    return ProjectState(snapshot, adrs, report, error, cfg.warnings)
