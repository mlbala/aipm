"""Phase derivation from `.pm/` files (C-4, ARCHITECTURE §7.1). Pure.

`derive_phase` walks the artifacts in order (requirements, PRD, design, plan, trust, tasks) and
stops at the first step that is missing, unapproved or stale. Staleness is transitive: when
`requirements.yaml` changes after the PRD was written, the PRD, the design and the plan are all
stale, and the report says so once, with the downstream impact.

`design_inputs` and `plan_inputs` tell those commands whether each upstream artifact is current
and approved. Approvals come from `approvals.yaml`, which is a record, not a control (SECURITY.md
§6): they decide the phase and when a role may run, never whether its input is wrapped.
"""

from dataclasses import dataclass
from enum import StrEnum

from aipm.domain.models import (
    APPROVED_NAMES,
    ApprovalGate,
    ArtifactKind,
    Phase,
    StateSnapshot,
    Task,
    TaskStatus,
)

_FINISHED = frozenset({TaskStatus.DONE, TaskStatus.SKIPPED})
_LABELS = {
    ArtifactKind.REQUIREMENTS: "requirements.yaml",
    ArtifactKind.PRD: "the PRD",
    ArtifactKind.ARCHITECTURE: "the architecture",
    ArtifactKind.THREAT_MODEL: "the threat model",
    ArtifactKind.TASKS: "the plan",
}
_GATES = {
    ArtifactKind.PRD: ApprovalGate.G1,
    ArtifactKind.ARCHITECTURE: ApprovalGate.G2,
    ArtifactKind.THREAT_MODEL: ApprovalGate.G2,
    ArtifactKind.ADR: ApprovalGate.G2,
    ArtifactKind.TASKS: ApprovalGate.G3,
}


class InputState(StrEnum):
    """Whether an upstream artifact may feed a role without `--accept-stale`."""

    OK = "ok"
    MISSING = "missing"
    UNAPPROVED = "unapproved"
    STALE = "stale"


@dataclass(frozen=True, slots=True)
class InputCheck:
    """One upstream artifact of a command, and why it cannot be used as it is."""

    kind: ArtifactKind
    artifact: str
    state: InputState
    sha256: str | None
    reason: str = ""

    @property
    def label(self) -> str:
        """The `Untrusted` source label: `approved:prd`, `stale:architecture` and so on."""
        prefix = "approved" if self.state is InputState.OK else self.state.value
        return f"{prefix}:{self.kind.value}"


@dataclass(frozen=True, slots=True)
class PhaseReport:
    """The current phase, what is stale and why, and the command to run next."""

    phase: Phase
    stale: tuple[ArtifactKind, ...] = ()
    next_command: str | None = None
    blockers: tuple[str, ...] = ()
    impacts: tuple[str, ...] = ()
    ready_task: str | None = None

    def to_data(self) -> dict[str, object]:
        """The `--json` payload."""
        return {
            "phase": self.phase.value,
            "stale": [k.value for k in self.stale],
            "next_command": self.next_command,
            "blockers": list(self.blockers),
            "impacts": list(self.impacts),
            "ready_task": self.ready_task,
        }


# ---------------------------------------------------------------- staleness


@dataclass(frozen=True, slots=True)
class _Staleness:
    stale: tuple[ArtifactKind, ...]
    impacts: tuple[str, ...]


def _direct(s: StateSnapshot) -> dict[ArtifactKind, str]:
    """Each artifact whose own `derived_from` no longer matches its upstream, with the cause."""
    h = s.hashes
    found: dict[ArtifactKind, str] = {}
    if s.prd is not None and s.prd.meta.derived_from.requirements != h.get(
        ArtifactKind.REQUIREMENTS
    ):
        found[ArtifactKind.PRD] = "requirements.yaml changed after the PRD was written"
    if s.architecture is not None and s.architecture.meta.derived_from.prd != h.get(
        ArtifactKind.PRD
    ):
        found[ArtifactKind.ARCHITECTURE] = "prd.md changed after the design was written"
    if s.threat_model is not None and s.threat_model.meta.derived_from.architecture != h.get(
        ArtifactKind.ARCHITECTURE
    ):
        found[ArtifactKind.THREAT_MODEL] = (
            "architecture.md changed after the threat model was written"
        )
    if s.tasks is not None:
        d = s.tasks.derived_from
        changed = [
            name
            for name, kind, value in (
                ("prd.md", ArtifactKind.PRD, d.prd),
                ("architecture.md", ArtifactKind.ARCHITECTURE, d.architecture),
                ("threat-model.md", ArtifactKind.THREAT_MODEL, d.threat_model),
            )
            if value != h.get(kind)
        ]
        if changed:
            found[ArtifactKind.TASKS] = f"{' and '.join(changed)} changed after the plan was made"
    return found


_ORDER = (
    ArtifactKind.PRD,
    ArtifactKind.ARCHITECTURE,
    ArtifactKind.THREAT_MODEL,
    ArtifactKind.TASKS,
)
_DOWNSTREAM = {
    ArtifactKind.PRD: (ArtifactKind.ARCHITECTURE, ArtifactKind.THREAT_MODEL, ArtifactKind.TASKS),
    ArtifactKind.ARCHITECTURE: (ArtifactKind.THREAT_MODEL, ArtifactKind.TASKS),
    ArtifactKind.THREAT_MODEL: (ArtifactKind.TASKS,),
    ArtifactKind.TASKS: (),
}


def _present(s: StateSnapshot, kind: ArtifactKind) -> bool:
    return {
        ArtifactKind.PRD: s.prd,
        ArtifactKind.ARCHITECTURE: s.architecture,
        ArtifactKind.THREAT_MODEL: s.threat_model,
        ArtifactKind.TASKS: s.tasks,
    }[kind] is not None


def _staleness(s: StateSnapshot) -> _Staleness:
    direct = _direct(s)
    stale: list[ArtifactKind] = []
    impacts: list[str] = []
    for kind in _ORDER:
        if kind not in direct or kind in stale:
            continue
        affected = [kind, *(k for k in _DOWNSTREAM[kind] if _present(s, k))]
        stale.extend(k for k in affected if k not in stale)
        names = [_LABELS[k] for k in affected]
        listed = names[0] if len(names) == 1 else ", ".join(names[:-1]) + " and " + names[-1]
        verb = "is" if len(names) == 1 else "are"
        impacts.append(f"{direct[kind]} → {listed} {verb} stale")
    return _Staleness(tuple(k for k in _ORDER if k in stale), tuple(impacts))


# ---------------------------------------------------------------- approvals


def _approved(s: StateSnapshot, kind: ArtifactKind) -> bool:
    return s.approvals.has(_GATES[kind], APPROVED_NAMES[kind], s.hashes.get(kind))


def design_approved(s: StateSnapshot) -> bool:
    """G2 holds for the current architecture, threat model and ADR directory."""
    return all(
        _approved(s, k)
        for k in (ArtifactKind.ARCHITECTURE, ArtifactKind.THREAT_MODEL, ArtifactKind.ADR)
    )


def _check(s: StateSnapshot, kind: ArtifactKind, stale: _Staleness, *, run: str) -> InputCheck:
    name = APPROVED_NAMES[kind]
    sha = s.hashes.get(kind)
    present = kind is ArtifactKind.ADR or _present(s, kind)
    if not present or sha is None:
        return InputCheck(kind, name, InputState.MISSING, None, f"{name} is missing; run {run}")
    if kind in stale.stale:
        return InputCheck(kind, name, InputState.STALE, sha, f"{name} is stale; run {run}")
    if not _approved(s, kind):
        gate = _GATES[kind].value
        return InputCheck(kind, name, InputState.UNAPPROVED, sha, f"{name} has no {gate} approval")
    return InputCheck(kind, name, InputState.OK, sha)


def design_inputs(s: StateSnapshot) -> tuple[InputCheck, ...]:
    """What `aipm design` reads: the PRD, approved (G1) and current."""
    return (_check(s, ArtifactKind.PRD, _staleness(s), run="`aipm discover`"),)


def plan_inputs(s: StateSnapshot) -> tuple[InputCheck, ...]:
    """What `aipm plan` reads: the PRD (G1), the architecture, threat model and ADRs (G2)."""
    stale = _staleness(s)
    return (
        _check(s, ArtifactKind.PRD, stale, run="`aipm discover`"),
        _check(s, ArtifactKind.ARCHITECTURE, stale, run="`aipm design --regenerate`"),
        _check(s, ArtifactKind.THREAT_MODEL, stale, run="`aipm design --regenerate`"),
        _check(s, ArtifactKind.ADR, stale, run="`aipm design --regenerate`"),
    )


# ---------------------------------------------------------------- tasks


def ready_tasks(tasks: list[Task]) -> list[Task]:
    """Tasks that may start: `todo`, with every dependency done or skipped, in ID order."""
    finished = {t.id for t in tasks if t.status in _FINISHED}
    return sorted(
        (t for t in tasks if t.status is TaskStatus.TODO and set(t.depends_on) <= finished),
        key=lambda t: t.id,
    )


def _tasks_phase(s: StateSnapshot, stale: _Staleness) -> PhaseReport:
    tasks = s.tasks.tasks if s.tasks is not None else []
    if tasks and all(t.status in _FINISHED for t in tasks):
        return PhaseReport(Phase.BUILT, stale.stale, None, impacts=stale.impacts)
    ready = ready_tasks(tasks)
    started = any(t.status is not TaskStatus.TODO for t in tasks)
    phase = Phase.BUILDING if started else Phase.PLAN_APPROVED
    if ready:
        first = ready[0].id
        return PhaseReport(phase, stale.stale, f"aipm prompt {first}", impacts=stale.impacts,
                           ready_task=first)  # fmt: skip
    blocked = [t.id for t in tasks if t.status is TaskStatus.BLOCKED]
    blockers = (f"no task is ready; blocked: {', '.join(blocked) or 'none'}",)
    return PhaseReport(phase, stale.stale, "aipm status", blockers, stale.impacts)


# ---------------------------------------------------------------- the walk


@dataclass(frozen=True, slots=True)
class _Walk:
    s: StateSnapshot
    stale: _Staleness

    def report(self, phase: Phase, command: str | None, *blockers: str) -> PhaseReport:
        return PhaseReport(phase, self.stale.stale, command, tuple(blockers), self.stale.impacts)

    def is_stale(self, *kinds: ArtifactKind) -> bool:
        return any(k in self.stale.stale for k in kinds)

    def prd(self) -> PhaseReport | None:
        s = self.s
        if s.requirements is None:  # pragma: no cover - derive_phase checks first
            return None
        if s.prd is None:
            ready = s.requirements.coverage.score >= s.coverage_threshold
            return self.report(
                Phase.REQUIREMENTS_READY if ready else Phase.DISCOVERING, "aipm discover"
            )
        if self.is_stale(ArtifactKind.PRD):
            return self.report(Phase.PRD_DRAFT, "aipm discover")
        blocking = ", ".join(q.id for q in s.requirements.open_questions if q.blocking)
        if blocking:
            reason = f"G1 is blocked by open questions: {blocking}"
            return self.report(Phase.PRD_DRAFT, "aipm discover", reason)
        if not _approved(s, ArtifactKind.PRD):
            return self.report(Phase.PRD_DRAFT, "aipm approve prd")
        return None

    def design(self) -> PhaseReport | None:
        s = self.s
        if s.architecture is None:
            return self.report(Phase.PRD_APPROVED, "aipm design")
        if s.threat_model is None or self.is_stale(
            ArtifactKind.ARCHITECTURE, ArtifactKind.THREAT_MODEL
        ):
            return self.report(Phase.DESIGN_DRAFT, "aipm design --regenerate")
        if not design_approved(s):
            return self.report(Phase.DESIGN_DRAFT, "aipm approve design")
        return None

    def plan(self) -> PhaseReport | None:
        s = self.s
        if s.tasks is None:
            return self.report(Phase.DESIGN_APPROVED, "aipm plan")
        if self.is_stale(ArtifactKind.TASKS):
            return self.report(Phase.PLAN_DRAFT, "aipm plan")
        if not _approved(s, ArtifactKind.TASKS):
            return self.report(Phase.PLAN_DRAFT, "aipm approve plan")
        if not s.trusted:
            reason = "the execution surface is not trusted"
            return self.report(Phase.PLAN_DRAFT, "aipm trust", reason)
        return None


def derive_phase(snapshot: StateSnapshot) -> PhaseReport:
    """Walk the artifacts in order and return the first missing, unapproved or stale step."""
    if not snapshot.initialized:
        return PhaseReport(Phase.UNINITIALIZED, next_command="aipm init")
    if snapshot.requirements is None:
        return PhaseReport(Phase.INITIALIZED, next_command="aipm discover")
    stale = _staleness(snapshot)
    walk = _Walk(snapshot, stale)
    for step in (walk.prd, walk.design, walk.plan):
        found = step()
        if found is not None:
            return found
    return _tasks_phase(snapshot, stale)
