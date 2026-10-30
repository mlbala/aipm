"""`aipm approve`: record a human approval of an artifact (G1-G3, context; ARCHITECTURE §7.2).

`approvals.yaml` is a team record of what was approved, pinned to sha256, never a security
control (SECURITY.md §6). `--yes` only skips the review prompt and never touches the trust store.
G1 (the PRD) arrived with build prompt 03, G2 (design) and G3 (plan) with prompt 04, and the
context files' managed blocks with prompt 05 (`aipm.app.sync_context.approve`).

An approval pins the exact bytes the user reviewed: the CLI passes the hashes it showed, and the
approval is refused if a file changed in between, or if the artifact is stale or its upstream is
not approved.

G2 covers `architecture.md`, `threat-model.md` and the `adr/` directory. After G2 a greenfield
project gets the chosen stack template's commands in `.pm/config.yaml`, which changes the
execution surface, so trust is needed again. G3 shows every command line from the trusted
config (never from the plan). Only an interactive G3 also records trust, through
`aipm.app.trust.confirm` with the full surface hash that was shown.
"""

import getpass
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Literal

from aipm.app import runtime
from aipm.app import trust as trust_use_case
from aipm.app.snapshot import read_snapshot, trust_of
from aipm.app.workspace import find_repo_root, require_initialized
from aipm.config.loader import load_config
from aipm.config.schema import Config
from aipm.config.stacks import load_stack
from aipm.domain.dag import MAX_TASKS, PlanRules, recheck_plan
from aipm.domain.errors import PolicyViolation, UsageError
from aipm.domain.models import (
    APPROVED_NAMES,
    AdrDoc,
    Approval,
    ApprovalGate,
    ApprovalsDoc,
    ArtifactKind,
    Mode,
    PrdDoc,
    Priority,
    RequirementsDoc,
    Severity,
    StaleOverride,
    StateSnapshot,
)
from aipm.domain.models.artifacts import OverrideReason
from aipm.domain.phase import InputCheck, InputState, plan_inputs
from aipm.reporting.plan_review import PlanFacts, plan_facts
from aipm.security.sanitize import sanitize_text
from aipm.state.layout import artifact_name
from aipm.state.store import FileStateStore
from aipm.state.yamlio import load_yaml

PRD_FILE = artifact_name(ArtifactKind.PRD)
_TARGETS = ("prd", "design", "plan", "context")
_MEDIUM_UP = frozenset({Severity.MEDIUM, Severity.HIGH, Severity.CRITICAL})


def approver() -> str:
    """Who approves: the local login name (a record, not an identity check)."""
    try:
        name = getpass.getuser()
    except Exception:  # getuser raises OSError or KeyError without a login name
        name = ""
    clean = " ".join(sanitize_text(name, source="login").text.split())[:200]
    return clean or "unknown"


def load_approvals(store: FileStateStore) -> ApprovalsDoc:
    """`approvals.yaml`, or an empty record."""
    if not store.exists(ArtifactKind.APPROVALS):
        return ApprovalsDoc()
    doc = store.load(ArtifactKind.APPROVALS)
    if not isinstance(doc, ApprovalsDoc):  # pragma: no cover - the store's mapping
        raise UsageError("approvals.yaml did not load as approvals")
    return doc


def is_approved(doc: ApprovalsDoc, gate: ApprovalGate, artifact: str, sha256: str) -> bool:
    """Whether this exact hash of the artifact has an approval for the gate."""
    return any(
        a.gate is gate and a.artifact == artifact and a.sha256 == sha256 for a in doc.approvals
    )


def record_approval(store: FileStateStore, gate: ApprovalGate, artifact: str, sha256: str) -> bool:
    """Append an approval; False if this hash was already approved. The caller holds the lock."""
    doc = load_approvals(store)
    if is_approved(doc, gate, artifact, sha256):
        return False
    entry = Approval(
        gate=gate, artifact=artifact, sha256=sha256, by=approver(), at=datetime.now(UTC)
    )
    store.save(doc.model_copy(update={"approvals": [*doc.approvals, entry]}))
    return True


@dataclass(frozen=True, slots=True)
class PrdReview:
    """What G1 shows, and whatever stops the approval."""

    repo_root: str
    sha256: str
    one_liner: str
    features: tuple[str, ...]
    non_functional: tuple[str, ...]
    assumptions: tuple[str, ...]
    open_questions: tuple[str, ...]
    blocking: tuple[str, ...]
    stale: bool
    approved: bool

    def to_data(self) -> dict[str, object]:
        """The `--json` payload."""
        return {
            "repo": self.repo_root,
            "artifact": PRD_FILE,
            "sha256": self.sha256,
            "features": list(self.features),
            "blocking": list(self.blocking),
            "stale": self.stale,
            "approved": self.approved,
        }


def _store(project: Path | None) -> FileStateStore:
    root = find_repo_root(project)
    require_initialized(root)
    return runtime.open_repo_store(root)


def _review(store: FileStateStore) -> PrdReview:
    if not store.exists(ArtifactKind.PRD):
        raise UsageError("there is no PRD to approve", hint="Run `aipm discover` first.")
    if not store.exists(ArtifactKind.REQUIREMENTS):
        raise UsageError("prd.md has no requirements.yaml", hint="Run `aipm discover`.")
    prd = store.load(ArtifactKind.PRD)
    requirements = store.load(ArtifactKind.REQUIREMENTS)
    sha = store.sha256(ArtifactKind.PRD)
    req_sha = store.sha256(ArtifactKind.REQUIREMENTS)
    if not isinstance(prd, PrdDoc) or not isinstance(requirements, RequirementsDoc) or not sha:
        raise UsageError("prd.md or requirements.yaml did not load")  # pragma: no cover
    return PrdReview(
        repo_root=str(store.repo_root),
        sha256=sha,
        one_liner=requirements.project.one_liner,
        features=tuple(f"{f.id} ({f.priority.value}): {f.title}" for f in prd.meta.features),
        non_functional=tuple(
            f"{n.id} ({n.category}): {n.statement}" for n in prd.meta.non_functional
        ),
        assumptions=tuple(f"{a.id}: {a.statement}" for a in requirements.assumptions),
        open_questions=tuple(
            f"{q.id}{' (blocking)' if q.blocking else ''}: {q.question}"
            for q in requirements.open_questions
        ),
        blocking=tuple(q.id for q in requirements.open_questions if q.blocking),
        stale=prd.meta.derived_from.requirements != req_sha,
        approved=is_approved(load_approvals(store), ApprovalGate.G1, PRD_FILE, sha),
    )


def check_target(artifact: str) -> None:
    """The PRD, the design, the plan and the context files' managed blocks can be approved."""
    if artifact not in _TARGETS:
        raise UsageError(f"cannot approve {artifact!r}", hint="Use prd, design, plan or context.")


def review_prd(project: Path | None) -> PrdReview:
    """The G1 summary of the current `prd.md`."""
    return _review(_store(project))


def approve_prd(project: Path | None, *, sha256: str) -> bool:
    """Record G1 for the PRD the user reviewed; False if it was already approved."""
    store = _store(project)
    with store.lock():
        review = _review(store)
        if review.sha256 != sha256:
            raise UsageError(
                "prd.md changed after it was shown; nothing was approved",
                hint="Run `aipm approve prd` again to review the current file.",
            )
        if review.stale:
            raise UsageError(
                "prd.md is stale: requirements.yaml changed after the PRD was written",
                hint="Run `aipm discover` to regenerate the PRD.",
            )
        if review.blocking:
            raise UsageError(
                f"G1 is blocked by open questions: {', '.join(review.blocking)}",
                hint="Answer them or turn them into assumptions with `aipm discover`.",
            )
        return record_approval(store, ApprovalGate.G1, PRD_FILE, sha256)


# ---------------------------------------------------------------- --accept-stale records


_REASONS = {
    InputState.STALE: OverrideReason.STALE,
    InputState.UNAPPROVED: OverrideReason.UNAPPROVED,
}


_OVERRIDE_COMMANDS: dict[str, Literal["design", "plan", "prompt"]] = {
    "design": "design",
    "plan": "plan",
    "prompt": "prompt",
}


def record_overrides(
    store: FileStateStore, command: str, checks: tuple[InputCheck, ...]
) -> list[str]:
    """Record each `--accept-stale` input in `approvals.yaml`; never counts as an approval."""
    entries: list[StaleOverride] = []
    for check in checks:
        reason = _REASONS.get(check.state)
        if reason is None or check.sha256 is None:
            continue
        entries.append(
            StaleOverride(
                command=_OVERRIDE_COMMANDS[command],
                artifact=check.artifact,
                sha256=check.sha256,
                reason=reason,
                by=approver(),
                at=datetime.now(UTC),
            )
        )
    if entries:
        doc = load_approvals(store)
        store.save(doc.model_copy(update={"overrides": [*doc.overrides, *entries]}))
    return [f"--accept-stale: ran on {c.artifact} ({c.state.value})" for c in checks
            if c.state in _REASONS]  # fmt: skip


def require_inputs(
    store: FileStateStore, command: str, checks: tuple[InputCheck, ...], *, accept_stale: bool
) -> list[str]:
    """Refuse missing input (exit 2), and stale or unapproved input unless `--accept-stale`."""
    for check in checks:
        if check.state is InputState.MISSING:
            raise UsageError(f"aipm {command} needs {check.reason}")
    bad = [c for c in checks if c.state is not InputState.OK]
    if bad and not accept_stale:
        raise UsageError(
            f"aipm {command} needs approved, current input: " + "; ".join(c.reason for c in bad),
            hint="Approve or regenerate it first, or pass --accept-stale to run on it anyway "
            "(the override is recorded in approvals.yaml).",
        )
    return record_overrides(store, command, checks)


# ---------------------------------------------------------------- G2: the design


def _mode(snapshot: StateSnapshot) -> Mode | None:
    return snapshot.requirements.mode if snapshot.requirements is not None else None


@dataclass(frozen=True, slots=True)
class DesignReview:
    """What G2 shows (ARCHITECTURE §7.2), the hashes it pins, and whatever stops it."""

    repo_root: str
    stack: tuple[str, ...]
    stack_template: str
    is_llm_app: bool
    components: tuple[str, ...]
    adrs: tuple[str, ...]
    threats: tuple[str, ...]
    hashes: tuple[tuple[str, str], ...]
    problems: tuple[str, ...]
    approved: bool
    greenfield: bool

    def to_data(self) -> dict[str, object]:
        """The `--json` payload."""
        return {
            "repo": self.repo_root,
            "stack_template": self.stack_template,
            "is_llm_app": self.is_llm_app,
            "components": list(self.components),
            "adrs": list(self.adrs),
            "threats": list(self.threats),
            "sha256": dict(self.hashes),
            "problems": list(self.problems),
            "approved": self.approved,
        }


def design_review_of(store: FileStateStore) -> DesignReview:
    """The G2 summary of the design on disk."""
    snapshot, adrs = read_snapshot(store, coverage_threshold=1.0, trusted=False)
    arch = snapshot.architecture
    if arch is None:
        raise UsageError("there is no design to approve", hint="Run `aipm design` first.")
    checks = plan_inputs(snapshot)
    problems = [c.reason for c in checks if c.state in (InputState.MISSING, InputState.STALE)]
    if checks[0].state is InputState.UNAPPROVED:
        problems.append("prd.md has no G1 approval; run `aipm approve prd` first")
    threats = snapshot.threat_model.meta.threats if snapshot.threat_model else []
    hashes = tuple((APPROVED_NAMES[c.kind], c.sha256) for c in checks[1:] if c.sha256 is not None)
    return DesignReview(
        repo_root=str(store.repo_root),
        stack=tuple(
            f"{k.replace('_', ' ')}: {v}" for k, v in arch.meta.stack.model_dump().items() if v
        ),
        stack_template=arch.meta.stack_template,
        is_llm_app=arch.meta.is_llm_app,
        components=tuple(
            f"{c.id} {c.name} ({', '.join(c.paths) or 'no paths'}): {c.responsibility}"
            for c in arch.meta.components
        ),
        adrs=tuple(f"{a.meta.id}: {a.meta.title}" for a in adrs),
        threats=tuple(
            f"{t.id} ({t.severity.value}, {t.component}): {t.title}"
            for t in threats
            if t.severity in _MEDIUM_UP
        ),
        hashes=hashes,
        problems=tuple(problems),
        approved=all(c.state is InputState.OK for c in checks),
        greenfield=_mode(snapshot) is Mode.GREENFIELD,
    )


def review_design(project: Path | None) -> DesignReview:
    """The G2 summary of the current design."""
    return design_review_of(_store(project))


def apply_stack(store: FileStateStore, template_name: str) -> bool:
    """Copy a built-in stack template's commands into the repo layer of `.pm/config.yaml`.

    Only the raw repo file is rewritten, never the merged config, so no user-level key can
    leak into the repository. Returns whether the file changed.
    """
    template = load_stack(template_name)
    text = store.read_text(ArtifactKind.CONFIG)
    raw: object = load_yaml(text, source=".pm/config.yaml") if text else {}
    if not isinstance(raw, dict):
        raise UsageError(".pm/config.yaml must be a YAML mapping")
    mapping: dict[object, object] = raw  # pyright: ignore[reportUnknownVariableType]
    layer: dict[str, object] = {str(k): v for k, v in mapping.items()}
    update = {
        "stack_template": template_name,
        **template.model_dump(mode="json", exclude_none=True),
    }
    before = Config.model_validate(layer).to_document()
    after = Config.model_validate({**layer, **update})
    if after.to_document() == before:
        return False
    store.save(after)
    return True


def record_design(store: FileStateStore, review: DesignReview) -> bool:
    """Record G2 for the reviewed hashes; copy the stack for greenfield. Returns stack copied."""
    for artifact, sha in review.hashes:
        record_approval(store, ApprovalGate.G2, artifact, sha)
    if review.greenfield:
        return apply_stack(store, review.stack_template)
    return False


def approve_design(project: Path | None, *, hashes: tuple[tuple[str, str], ...]) -> bool:
    """Record G2 for the design the user reviewed. Returns whether the stack was copied."""
    store = _store(project)
    with store.lock():
        review = design_review_of(store)
        if review.hashes != hashes:
            raise UsageError(
                "the design changed after it was shown; nothing was approved",
                hint="Run `aipm approve design` again to review the current files.",
            )
        if review.problems:
            raise UsageError("G2 cannot be approved: " + "; ".join(review.problems))
        return record_design(store, review)


# ---------------------------------------------------------------- G3: the plan


@dataclass(frozen=True, slots=True)
class PlanReview:
    """What G3 shows (ARCHITECTURE §7.2, SECURITY.md §7.5), and whatever stops it."""

    repo_root: str
    sha256: str
    facts: PlanFacts
    surface_lines: tuple[str, ...]
    surface_hash: str | None
    surface_error: str | None
    trusted: bool
    problems: tuple[str, ...]
    approved: bool
    warnings: tuple[str, ...] = ()
    """Config warnings, shown before G3 asks for trust (ARCHITECTURE §15)."""

    def to_data(self) -> dict[str, object]:
        """The `--json` payload."""
        return {
            "repo": self.repo_root,
            "artifact": APPROVED_NAMES[ArtifactKind.TASKS],
            "sha256": self.sha256,
            "tasks": len(self.facts.rows) - 1,
            "depth": self.facts.depth,
            "width": self.facts.width,
            "deps_add": list(self.facts.deps_add),
            "test_or_config": list(self.facts.test_or_config),
            "surface_hash": self.surface_hash,
            "surface_error": self.surface_error,
            "trusted": self.trusted,
            "problems": list(self.problems),
            "approved": self.approved,
        }


def plan_rules(snapshot: StateSnapshot, cfg: Config, *, max_tasks: int = MAX_TASKS) -> PlanRules:
    """The plan validator's rules, from the snapshot's PRD and threat model and the config."""
    features = snapshot.prd.meta.features if snapshot.prd is not None else []
    nfrs = snapshot.prd.meta.non_functional if snapshot.prd is not None else []
    threats = snapshot.threat_model.meta.threats if snapshot.threat_model is not None else []
    return PlanRules(
        gate_menu=tuple(cfg.gates),
        features=frozenset(f.id for f in features),
        must_features=frozenset(f.id for f in features if f.priority is Priority.MUST),
        nfrs=frozenset(n.id for n in nfrs),
        threats=frozenset(t.id for t in threats),
        threats_to_trace=frozenset(t.id for t in threats if t.severity in _MEDIUM_UP),
        serialized_paths=tuple(cfg.plan.serialized_paths),
        extra_protected=tuple(cfg.security.extra_protected_paths),
        max_tasks=max_tasks,
    )


def plan_review_of(store: FileStateStore) -> PlanReview:
    """The G3 summary: the plan from `tasks.yaml`, the command lines from the trusted config."""
    loaded = load_config(store.repo_root)
    report, error = trust_of(store.repo_root, loaded)
    snapshot, _ = read_snapshot(
        store, coverage_threshold=1.0, trusted=bool(report and report.trusted)
    )
    tasks = snapshot.tasks
    sha = snapshot.hashes.get(ArtifactKind.TASKS)
    if tasks is None or sha is None:
        raise UsageError("there is no plan to approve", hint="Run `aipm plan` first.")
    problems = [
        f"{c.artifact} is {c.state.value}" for c in plan_inputs(snapshot)
        if c.state is not InputState.OK
    ]  # fmt: skip
    d = tasks.derived_from
    if (d.prd, d.architecture, d.threat_model) != (
        snapshot.hashes.get(ArtifactKind.PRD),
        snapshot.hashes.get(ArtifactKind.ARCHITECTURE),
        snapshot.hashes.get(ArtifactKind.THREAT_MODEL),
    ):
        problems.append("tasks.yaml is stale: its upstream changed; run `aipm plan`")
    problems.extend(
        f"tasks.yaml breaks a plan rule: {p}"
        for p in recheck_plan(tasks.tasks, plan_rules(snapshot, loaded.config))
    )
    return PlanReview(
        repo_root=str(store.repo_root),
        sha256=sha,
        facts=plan_facts(tasks.tasks, test_roots=loaded.config.test_roots),
        surface_lines=report.lines if report is not None else (),
        surface_hash=report.surface_hash if report is not None else None,
        surface_error=error,
        trusted=bool(report and report.trusted),
        problems=tuple(problems),
        approved=snapshot.approvals.has(ApprovalGate.G3, APPROVED_NAMES[ArtifactKind.TASKS], sha),
        warnings=loaded.warnings,
    )


def review_plan(project: Path | None) -> PlanReview:
    """The G3 summary of the current plan."""
    return plan_review_of(_store(project))


def approve_plan(
    project: Path | None, *, sha256: str, trust_surface: str | None = None
) -> tuple[bool, bool]:
    """Record G3 for the plan the user reviewed; returns (recorded, trusted).

    `trust_surface` is the full surface hash an interactive user confirmed: only then is trust
    recorded too. `--yes` passes None, so it records the approval only.
    """
    store = _store(project)
    with store.lock():
        review = plan_review_of(store)
        if review.sha256 != sha256:
            raise UsageError(
                "tasks.yaml changed after it was shown; nothing was approved",
                hint="Run `aipm approve plan` again to review the current plan.",
            )
        if review.problems:
            raise UsageError("G3 cannot be approved: " + "; ".join(review.problems))
        if trust_surface is not None and review.surface_hash != trust_surface:
            raise PolicyViolation(
                "the execution surface changed after it was shown; nothing was approved",
                hint="Run `aipm approve plan` again to review the current commands.",
            )
        recorded = record_approval(
            store, ApprovalGate.G3, APPROVED_NAMES[ArtifactKind.TASKS], sha256
        )
    trusted = review.trusted
    if trust_surface is not None and not trusted:
        trusted = trust_use_case.confirm(project, trust_surface).trusted
    return recorded, trusted


__all__ = [
    "AdrDoc",
    "DesignReview",
    "PlanReview",
    "PrdReview",
    "apply_stack",
    "approve_design",
    "approve_plan",
    "approve_prd",
    "approver",
    "check_target",
    "design_review_of",
    "is_approved",
    "load_approvals",
    "plan_review_of",
    "plan_rules",
    "record_approval",
    "record_design",
    "record_overrides",
    "require_inputs",
    "review_design",
    "review_plan",
    "review_prd",
]
