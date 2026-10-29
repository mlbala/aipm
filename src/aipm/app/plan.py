"""`aipm plan`: the task graph, `tasks.yaml`, `worksheet.md` and G3 (ARCHITECTURE §9, §7.2).

The PRD (G1) and the design (G2) must be approved and current, unless `--accept-stale`, which
is recorded in `approvals.yaml`. Each reaches the planner wrapped as `Untrusted` with its label
(`approved:prd`, `stale:architecture`, ...). The planner sees the gate menu by name only.

Its reply goes through `aipm.domain.dag.validate_plan`, the control that matters: if any rule
fails, the planner gets one repair attempt with aipm's own description of each problem. If the
plan still fails, nothing is written: a policy issue (unknown gate, unsafe path, bad package
name) exits 6 and is recorded as a `policy_violation` event; anything else exits 1.

G3 shows the plan facts and every command line from the trusted config. `--yes` records the
approval only; an interactive approval also records trust for the surface that was shown.
"""

from collections.abc import Sequence
from dataclasses import dataclass, field
from pathlib import Path
from typing import Protocol

from aipm.app import runtime
from aipm.app import trust as trust_use_case
from aipm.app.approve import PlanReview, plan_review_of, record_approval, require_inputs
from aipm.app.guards import check_injection, repair_block
from aipm.app.snapshot import read_snapshot
from aipm.app.workspace import find_repo_root, require_initialized
from aipm.config.loader import load_config
from aipm.config.schema import Config
from aipm.domain.dag import MAX_TASKS, PlanRules, PlanValidation, validate_plan
from aipm.domain.errors import AipmError, PolicyViolation, UsageError
from aipm.domain.models import (
    APPROVED_NAMES,
    ApprovalGate,
    ArtifactKind,
    Priority,
    RoleName,
    SecurityEventKind,
    Severity,
    StateSnapshot,
    TasksDerivedFrom,
    TasksDoc,
    TaskStatus,
)
from aipm.domain.phase import InputCheck, plan_inputs
from aipm.llm.cost import UsageLedger
from aipm.llm.gateway import TokenBudget, open_gateway
from aipm.reporting.worksheet import WORKSHEET_FILE, render_worksheet
from aipm.roles import planner
from aipm.roles.planner import MenuGate, PlanDraft
from aipm.security.untrusted import Untrusted
from aipm.state.store import FileStateStore, normalized_sha256, open_store
from aipm.state.yamlio import dump_yaml

_MEDIUM_UP = frozenset({Severity.MEDIUM, Severity.HIGH, Severity.CRITICAL})
_EVENT_ISSUES = 20


class PlanRejected(AipmError):
    """The plan still broke a rule after the repair attempt (exit 1)."""

    code = "PLAN_REJECTED"


class PlanPrompter(Protocol):
    """The interactive side of `aipm plan`, implemented by the CLI."""

    def confirm_risk(self, role: str, excerpts: Sequence[str]) -> bool:
        """Warn about suspected prompt injection; True continues."""
        ...

    def approve_plan(self, review: PlanReview, changes: Sequence[str]) -> bool:
        """G3: show the plan, its commands and the validator's changes, then ask."""
        ...


@dataclass(frozen=True, slots=True)
class PlanOptions:
    """The command's flags."""

    max_tasks: int | None = None
    accept_risk: bool = False
    accept_stale: bool = False
    yes: bool = False


@dataclass(frozen=True, slots=True)
class PlanResult:
    """What `aipm plan` did, for the CLI to report."""

    repo_root: str
    tasks: int
    changes: tuple[str, ...]
    written: tuple[str, ...]
    approval: str
    trusted: bool
    review: PlanReview
    usage: dict[str, object]
    warnings: tuple[str, ...]
    notes: tuple[str, ...]

    def to_data(self) -> dict[str, object]:
        """The `--json` payload."""
        return {
            "repo": self.repo_root,
            "tasks": self.tasks,
            "changes": list(self.changes),
            "written": list(self.written),
            "approval": self.approval,
            "trusted": self.trusted,
            "plan": self.review.to_data(),
            "usage": self.usage,
            "warnings": list(self.warnings),
            "notes": list(self.notes),
        }


def _max_tasks(value: int | None) -> int:
    if value is None:
        return MAX_TASKS
    if not 1 <= value <= MAX_TASKS:
        raise UsageError(f"--max-tasks must be between 1 and {MAX_TASKS}")
    return value


def run(project: Path | None, *, options: PlanOptions, prompter: PlanPrompter | None) -> PlanResult:
    """Run the use case. `prompter` is None in a non-interactive run."""
    root = find_repo_root(project)
    require_initialized(root)
    max_tasks = _max_tasks(options.max_tasks)
    loaded = load_config(root)
    store = open_store(root, redactor=runtime.user_redactor())
    with store.lock():
        snapshot, _ = read_snapshot(
            store, coverage_threshold=loaded.config.discover.coverage_threshold, trusted=False
        )
        checks = plan_inputs(snapshot)
        warnings = list(loaded.warnings)
        warnings += require_inputs(store, "plan", checks, accept_stale=options.accept_stale)
        if snapshot.tasks is not None and any(
            t.status is not TaskStatus.TODO for t in snapshot.tasks.tasks
        ):
            raise UsageError(
                "work on the current plan has started, so aipm plan will not replace it",
                hint="Manage started tasks with `aipm task` (v0.2), or reset them first.",
            )
        if not loaded.config.gates:
            raise UsageError(
                "there is no gate menu in .pm/config.yaml",
                hint="Approve the design (a greenfield project gets its stack's gates), or run "
                "`aipm init --stack NAME --force`.",
            )
        session = _Plan(root=root, cfg=loaded.config, store=store, prompter=prompter,
                        options=options, snapshot=snapshot, checks=checks, max_tasks=max_tasks,
                        warnings=warnings)  # fmt: skip
        return session.run()


@dataclass
class _Plan:
    root: Path
    cfg: Config
    store: FileStateStore
    prompter: PlanPrompter | None
    options: PlanOptions
    snapshot: StateSnapshot
    checks: tuple[InputCheck, ...]
    max_tasks: int
    warnings: list[str]
    notes: list[str] = field(default_factory=list[str])
    ledger: UsageLedger = field(default_factory=UsageLedger)

    @property
    def project(self) -> str:
        reqs = self.snapshot.requirements
        return reqs.project.name if reqs is not None else (self.cfg.project.name or "project")

    def run(self) -> PlanResult:
        validation = self._plan()
        doc = TasksDoc(derived_from=self._derived_from(), tasks=list(validation.tasks))
        self.store.save(doc)
        saved = self.store.load(ArtifactKind.TASKS)
        if isinstance(saved, TasksDoc):
            self.store.write_text(WORKSHEET_FILE, render_worksheet(saved))
        review = plan_review_of(self.store)
        approval, trusted = self._g3(review, validation.changes)
        written = ("tasks.yaml", WORKSHEET_FILE) + (("approvals.yaml",) if approval == "approved"
                                                     else ())  # fmt: skip
        return PlanResult(
            repo_root=str(self.root),
            tasks=len(validation.tasks),
            changes=validation.changes,
            written=written,
            approval=approval,
            trusted=trusted,
            review=review,
            usage=self.ledger.to_data(),
            warnings=tuple(self.warnings),
            notes=tuple(self.notes),
        )

    # ------------------------------------------------------------ inputs

    def _derived_from(self) -> TasksDerivedFrom:
        prd, arch, tm, _ = self.checks
        if prd.sha256 is None or arch.sha256 is None or tm.sha256 is None:  # pragma: no cover
            raise UsageError("an upstream artifact is missing")
        return TasksDerivedFrom(prd=prd.sha256, architecture=arch.sha256, threat_model=tm.sha256)

    def _text(self, check: InputCheck) -> Untrusted:
        text = self.store.read_text(check.kind)
        if text is None or normalized_sha256(text.encode("utf-8")) != check.sha256:
            raise UsageError(f"{check.artifact} changed while aipm was reading it; nothing written")
        return Untrusted(text, source=check.label)

    def _rules(self) -> PlanRules:
        s = self.snapshot
        features = s.prd.meta.features if s.prd is not None else []
        nfrs = s.prd.meta.non_functional if s.prd is not None else []
        threats = s.threat_model.meta.threats if s.threat_model is not None else []
        return PlanRules(
            gate_menu=tuple(self.cfg.gates),
            features=frozenset(f.id for f in features),
            must_features=frozenset(f.id for f in features if f.priority is Priority.MUST),
            nfrs=frozenset(n.id for n in nfrs),
            threats=frozenset(t.id for t in threats),
            threats_to_trace=frozenset(t.id for t in threats if t.severity in _MEDIUM_UP),
            serialized_paths=tuple(self.cfg.plan.serialized_paths),
            extra_protected=tuple(self.cfg.security.extra_protected_paths),
            max_tasks=self.max_tasks,
        )

    def _settings(self) -> Untrusted:
        data = {
            "test_roots": list(self.cfg.test_roots),
            "serialized_paths": list(self.cfg.plan.serialized_paths),
            "extra_protected_paths": list(self.cfg.security.extra_protected_paths),
        }
        return Untrusted(dump_yaml(data), source="config:plan")

    # ------------------------------------------------------------ the planner and the validator

    def _plan(self) -> PlanValidation:
        prd, arch, tm, _ = self.checks
        rules = self._rules()
        base = planner.PlannerInput(
            project=self.project,
            prd=self._text(prd),
            architecture=self._text(arch),
            threat_model=self._text(tm),
            gates=tuple(MenuGate(name, gate.required) for name, gate in self.cfg.gates.items()),
            must_features=tuple(sorted(rules.must_features)),
            threats_to_trace=tuple(sorted(rules.threats_to_trace)),
            settings=self._settings(),
            max_tasks=self.max_tasks,
        )
        gateway = open_gateway(self.cfg.llm, redactor=self.store.redactor, ledger=self.ledger)
        role = planner.create()
        problems: Untrusted | None = None
        validation = PlanValidation()
        for attempt in range(2):
            inp = base if problems is None else _with_problems(base, problems)
            budget = TokenBudget(self.cfg.budget.run_tokens - self.ledger.total_tokens)
            draft = gateway.run(RoleName.PLANNER, role.render(inp), PlanDraft, budget=budget).value
            draft = role.postprocess(draft, inp)
            self._check_injection(draft.injection_suspected)
            validation = validate_plan(draft.tasks, rules)
            self._record_signals(validation)
            if validation.ok:
                return validation
            if attempt == 0:
                problems = repair_block([issue.repair for issue in validation.issues])
        self._reject(validation)
        return validation  # pragma: no cover - _reject always raises

    def _check_injection(self, excerpts: Sequence[str]) -> None:
        confirm = self.prompter.confirm_risk if self.prompter is not None else None
        check_injection(self.store, RoleName.PLANNER, excerpts, confirm=confirm,
                        accept_risk=self.options.accept_risk, warnings=self.warnings)  # fmt: skip

    def _record_signals(self, validation: PlanValidation) -> None:
        if validation.removed_characters:
            self.store.append_event(
                SecurityEventKind.INJECTION_SIGNAL,
                source="llm:planner",
                detail=f"the plan validator removed {validation.removed_characters} control, "
                "escape or invisible characters from the planner's text",
            )
            self.warnings.append(
                f"removed {validation.removed_characters} control, escape or invisible characters "
                "from the plan text; see `aipm status`"
            )
        security = validation.security_issues
        if security:
            self.store.append_event(
                SecurityEventKind.POLICY_VIOLATION,
                source="llm:planner",
                detail=f"the planner proposed {len(security)} "
                f"{'item' if len(security) == 1 else 'items'} outside the policy",
                data={"issues": [i.message for i in security[:_EVENT_ISSUES]]},
            )

    def _reject(self, validation: PlanValidation) -> None:
        messages = [issue.message for issue in validation.issues]
        data: dict[str, object] = {"issues": messages, "changes": list(validation.changes)}
        hint = "Nothing was written. Review the PRD and design, then run `aipm plan` again."
        if validation.security_issues:
            raise PolicyViolation(
                f"the plan asks for {len(validation.security_issues)} things the policy forbids "
                "(gates outside the menu, unsafe paths or bad package names)",
                hint=hint,
                data=data,
            )
        raise PlanRejected(
            f"the plan breaks {len(messages)} rules after the repair attempt", hint=hint, data=data
        )

    # ------------------------------------------------------------ G3

    def _g3(self, review: PlanReview, changes: Sequence[str]) -> tuple[str, bool]:
        """Returns (approved | pending, trusted). Only an interactive approval records trust."""
        name = APPROVED_NAMES[ArtifactKind.TASKS]
        hash12 = review.surface_hash[:12] if review.surface_hash else None
        trust_hint = (
            f"run `aipm trust --confirm {hash12}` after reviewing `aipm trust --show`"
            if hash12
            else f"the execution surface cannot be trusted: {review.surface_error}"
        )
        if review.problems:
            self.notes.append("G3 cannot be approved yet: " + "; ".join(review.problems))
            return "pending", review.trusted
        if review.approved:
            return "approved", review.trusted
        if self.options.yes:
            record_approval(self.store, ApprovalGate.G3, name, review.sha256)
            if not review.trusted:
                self.notes.append(
                    f"G3 recorded without trust (--yes never grants it); {trust_hint}"
                )
            return "approved", review.trusted
        if self.prompter is not None and self.prompter.approve_plan(review, changes):
            if review.surface_hash is None:
                raise PolicyViolation(trust_hint)
            record_approval(self.store, ApprovalGate.G3, name, review.sha256)
            if review.trusted:
                return "approved", True
            report = trust_use_case.confirm(self.root, review.surface_hash)
            return "approved", report.trusted
        self.notes.append("review .pm/worksheet.md, then run `aipm approve plan`")
        return "pending", review.trusted


def _with_problems(base: planner.PlannerInput, problems: Untrusted) -> planner.PlannerInput:
    return planner.PlannerInput(
        project=base.project, prd=base.prd, architecture=base.architecture,
        threat_model=base.threat_model, gates=base.gates, must_features=base.must_features,
        threats_to_trace=base.threats_to_trace, settings=base.settings, max_tasks=base.max_tasks,
        problems=problems,
    )  # fmt: skip


__all__ = ["PlanOptions", "PlanPrompter", "PlanRejected", "PlanResult", "run"]
