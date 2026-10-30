"""`aipm verify <T-ID>`: post-change checks and gates for one task, in manual mode (§12.7, §13).

Order: trust (exit 6) → sandbox (exit 8 when required and missing) → the `.pm/` lock → the
approved, current plan (G3, or `--accept-stale`, recorded) → the task is in progress and has an
attempt snapshot (exit 2 otherwise) → the integrity hashes, before git runs → the change set →
the post-change checks. Then:

- **severe** violation: the task is blocked (`policy_violation`), each violation is a security
  event, exit 6. No gate runs;
- otherwise the gates run (no fail-fast), then the checks run again, because gates execute code
  the agent wrote: a new severe violation blocks the task (exit 6). The attempt is counted and
  its report, logs and journal are saved in `.pm/runs/<run-id>/`.

The task is `done` only if every required gate (the menu's, and every gate the task names)
passed, the AC reviewer vetoed nothing, there was no minor violation and `--gate` was not given.
`--commit` then commits the task's changes through the hardened git wrapper, with trailers.
Otherwise exit 3; or 8 when a required scanner is missing; or 4 when the AC reviewer reported
suspected prompt injection and `--accept-risk` was not given. Manual verify never reverts
anything in your tree.
"""

import secrets
import shutil
import tempfile
from collections.abc import Sequence
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path

from pydantic import JsonValue

from aipm.app import runtime
from aipm.app.approve import approver, load_approvals, require_inputs
from aipm.app.attempt import changes_since, check_policy
from aipm.app.snapshot import read_snapshot
from aipm.app.trust import require_trusted
from aipm.app.workspace import find_repo_root, require_initialized
from aipm.config.loader import load_config
from aipm.config.schema import Config
from aipm.domain.errors import (
    AipmError,
    HumanInputRequired,
    MissingCapability,
    PolicyViolation,
    UsageError,
    VerificationFailed,
)
from aipm.domain.ids import is_valid_id
from aipm.domain.models import (
    AcOverride,
    Blocked,
    BlockedReason,
    BuiltinGate,
    ChangeSet,
    ChangeStatus,
    Done,
    GateFinding,
    GateReport,
    GateResult,
    GateStatus,
    GateWorkspace,
    JournalEvent,
    JournalEventType,
    RoleName,
    SecurityEventKind,
    Severity,
    Task,
    TasksDoc,
    TaskStatus,
)
from aipm.domain.models.snapshot import StateSnapshot
from aipm.domain.phase import prompt_inputs
from aipm.execution import git
from aipm.execution.sandbox import Runtime, resolve_sandbox
from aipm.gates.builtin.ac_review import Reviewer
from aipm.gates.context import GateContext
from aipm.gates.runner import GateRun, run_gates
from aipm.llm.gateway import TokenBudget, open_gateway
from aipm.reporting.worksheet import WORKSHEET_FILE, render_worksheet
from aipm.roles import ac_reviewer
from aipm.roles.ac_reviewer import ACReview, ACReviewInput
from aipm.security.diff_checks import Kind, Level, Violation, check_changes, severe
from aipm.security.paths import is_within
from aipm.security.sanitize import sanitize_text
from aipm.state.attempts import AttemptSnapshot, load_snapshot
from aipm.state.store import FileStateStore
from aipm.state.yamlio import dump_yaml

MAX_EVENTS = 20
CHECKS = "checks"

type Events = list[tuple[JournalEventType, dict[str, JsonValue]]]


@dataclass(frozen=True, slots=True)
class VerifyOptions:
    """The command's arguments and flags."""

    task_id: str
    commit: bool = False
    base: str | None = None
    gate: str | None = None
    override_ac: str | None = None
    reason: str | None = None
    accept_risk: bool = False
    accept_stale: bool = False
    no_cache: bool = False


@dataclass(slots=True)
class VerifyResult:
    """What `verify` found and did, for the CLI (and the JSON envelope)."""

    task: str
    outcome: str
    run_id: str
    attempt: int
    base_sha: str
    report: GateReport
    violations: list[Violation] = field(default_factory=list[Violation])
    commit: str | None = None
    saved: str | None = None
    sandboxed: bool = False
    warnings: list[str] = field(default_factory=list[str])

    def to_data(self) -> dict[str, object]:
        """The `--json` payload (ARCHITECTURE §16.2)."""
        return {
            "task": self.task,
            "outcome": self.outcome,
            "run_id": self.run_id,
            "attempt": self.attempt,
            "base_sha": self.base_sha,
            "sandboxed": self.sandboxed,
            "violations": [
                {"kind": v.kind.value, "level": v.level.value, "path": v.path, "detail": v.detail}
                for v in self.violations
            ],
            "gates": [g.model_dump(mode="json", exclude={"output"}) for g in self.report.gates],
            "commit": self.commit,
            "report": self.saved,
            "warnings": list(self.warnings),
        }


def _check_options(options: VerifyOptions, cfg: Config) -> None:
    if not is_valid_id("task", options.task_id):
        raise UsageError(f"{options.task_id!r} is not a task ID such as T-007")
    if (options.override_ac is None) != (options.reason is None):
        raise UsageError("--override-ac and --reason go together")
    if options.reason is not None and not options.reason.strip():
        raise UsageError("--reason must say why the override is justified")
    if options.gate is not None and options.gate not in cfg.gates:
        known = ", ".join(sorted(cfg.gates)) or "none"
        raise UsageError(f"there is no gate {options.gate!r} in the menu", hint=f"Gates: {known}")


def _check_task(task: Task, options: VerifyOptions) -> None:
    if task.status is TaskStatus.IN_PROGRESS:
        criteria = {c.id for c in task.acceptance}
        if options.override_ac is not None and options.override_ac not in criteria:
            raise UsageError(f"{options.override_ac} is not an acceptance criterion of {task.id}")
        return
    hints = {
        TaskStatus.TODO: f"Start it with `aipm prompt {task.id}`.",
        TaskStatus.DONE: f"It is verified; `aipm task reset {task.id}` starts it again.",
        TaskStatus.SKIPPED: f"`aipm task reset {task.id}` starts it again.",
        TaskStatus.BLOCKED: f"Review it, then `aipm task unblock {task.id}`.",
    }
    raise UsageError(f"{task.id} is {task.status.value}, not in progress", hint=hints[task.status])


def _attempt_dir(root: Path) -> Path:
    """A private (0700) temp dir for this attempt, outside the repository."""
    path = Path(tempfile.mkdtemp(prefix="aipm-verify-"))
    if is_within(path, root):
        shutil.rmtree(path, ignore_errors=True)
        raise PolicyViolation(
            "the temporary directory is inside the repository",
            hint="Check TMPDIR, which a repository .env loaded by a tool such as pipenv can set.",
        )
    return path


def new_run_id() -> str:
    """`r-YYYYMMDD-HHMM-xxxx`."""
    return f"r-{datetime.now(UTC):%Y%m%d-%H%M}-{secrets.token_hex(2)}"


def checks_result(violations: Sequence[Violation]) -> GateResult:
    """The post-change checks as a report entry, so `prompt --fix` sends them as feedback."""
    findings = [
        GateFinding(
            tool="checks",
            rule=v.kind.value,
            path=v.path[:512],
            message=v.detail[:500],
            severity=Severity.CRITICAL if v.level is Level.SEVERE else Severity.MEDIUM,
        )
        for v in violations[:100]
    ]
    worst = "severe" if severe(violations) else "minor"
    summary = f"{len(violations)} {worst} post-change violation(s)" if violations else "clean"
    lines = (f"{v.level.value}: {v.kind.value}: {v.path}: {v.detail}" for v in violations)
    return GateResult(
        name=CHECKS,
        status=GateStatus.FAIL if violations else GateStatus.PASS,
        required=True,
        summary=summary,
        findings=findings,
        output="\n".join(lines)[:65_536],
    )


def _reviewer(cfg: Config, store: FileStateStore, *, no_cache: bool) -> tuple[Reviewer | None, str]:
    """The AC reviewer through the LLM gateway, or why it cannot run."""
    if not any(g.builtin is BuiltinGate.AC_REVIEW for g in cfg.gates.values()):
        return None, "the gate menu has no ac_review gate"
    try:
        gateway = open_gateway(
            cfg.llm, redactor=store.redactor, cache=None if no_cache else runtime.llm_cache(store)
        )
    except AipmError as exc:
        return None, f"the AC reviewer cannot run: {exc.message}"
    role = ac_reviewer.create()
    budget = TokenBudget(cfg.budget.run_tokens)

    def review(inp: ACReviewInput) -> ACReview:
        result = gateway.run(
            RoleName.AC_REVIEWER,
            role.render(inp),
            ACReview,
            budget=budget,
            template_version=role.template_version,
        )
        return role.postprocess(result.value, inp)

    return review, ""


def _hashes(root: Path, changes: ChangeSet) -> dict[str, str | None]:
    """The task's changed files as the gates are about to see them: what is scanned and linted
    must be what is saved and committed (step 06 security review)."""
    return {
        c.path: git.hash_path(root / c.path)
        for c in changes.files
        if c.status is not ChangeStatus.DELETED and not c.path.startswith(".pm/")
    }


def _save_tasks(store: FileStateStore, tasks: TasksDoc, task: Task) -> None:
    doc = tasks.model_copy(update={"tasks": [task if t.id == task.id else t for t in tasks.tasks]})
    store.save(doc)
    store.write_text(WORKSHEET_FILE, render_worksheet(doc))


def _journal(result: "VerifyResult", events: Events) -> str:
    now = datetime.now(UTC)
    lines = [
        JournalEvent(
            seq=i, ts=now, run=result.run_id, type=kind, task=result.task,
            attempt=result.attempt, data=data,
        ).model_dump_json()
        for i, (kind, data) in enumerate(events)
    ]  # fmt: skip
    return "\n".join(lines) + "\n"


def _save_run(
    store: FileStateStore, result: VerifyResult, outputs: dict[str, str], events: Events
) -> None:
    """Save each gate's full output, the report and the journal in the run directory."""
    base = ["gates", result.task, str(result.attempt)]
    refs: dict[str, str] = {}
    for name, text in outputs.items():
        if text:
            refs[name] = store.save_run_text(result.run_id, [*base, f"{name}.log"], text)
    gates = [g.model_copy(update={"output_ref": refs.get(g.name)}) for g in result.report.gates]
    result.report = result.report.model_copy(update={"gates": gates})
    document = result.report.model_dump(mode="json")
    result.saved = store.save_run_text(result.run_id, [*base, "report.yaml"], dump_yaml(document))
    store.save_run_text(result.run_id, ["journal.jsonl"], _journal(result, events))


def _record_violations(store: FileStateStore, task: Task, violations: Sequence[Violation]) -> None:
    for violation in severe(violations)[:MAX_EVENTS]:
        store.append_event(
            SecurityEventKind.POST_CHANGE_VIOLATION,
            source=f"verify:{task.id}",
            detail=f"{violation.kind.value}: {violation.path}: {violation.detail}",
            data={"kind": violation.kind.value, "path": violation.path[:512]},
        )


def _record_override(
    store: FileStateStore, task: Task, options: VerifyOptions, run_id: str, *, applied: bool
) -> None:
    criterion, reason = options.override_ac or "", options.reason or ""
    clean = " ".join(sanitize_text(reason, source="--reason").text.split())[:300]
    entry = AcOverride(
        task=task.id, criterion=criterion, reason=clean, run_id=run_id, by=approver(),
        at=datetime.now(UTC),
    )  # fmt: skip
    doc = load_approvals(store)
    store.save(doc.model_copy(update={"ac_overrides": [*doc.ac_overrides, entry]}))
    store.append_event(
        SecurityEventKind.OVERRIDE,
        source=f"verify:{task.id}",
        detail=f"--override-ac {criterion}: {clean}",
        data={"criterion": criterion, "applied": applied, "run": run_id},
    )


def _stop(result: VerifyResult, error: type[AipmError], message: str, hint: str) -> AipmError:
    return error(message, hint=hint, data=result.to_data())


@dataclass(slots=True)
class _Verify:
    """One verify run, under the lock."""

    root: Path
    cfg: Config
    store: FileStateStore
    options: VerifyOptions
    temp: Path
    sandbox: Runtime | None
    warnings: list[str]

    def _task(self) -> tuple[TasksDoc, Task, AttemptSnapshot, StateSnapshot]:
        state, _ = read_snapshot(
            self.store, coverage_threshold=self.cfg.discover.coverage_threshold, trusted=True
        )
        tasks = state.tasks
        wanted = self.options.task_id
        task = next((t for t in tasks.tasks if t.id == wanted), None) if tasks else None
        if tasks is None or task is None:
            raise UsageError(f"there is no task {wanted} in .pm/tasks.yaml")
        _check_task(task, self.options)
        snapshot = load_snapshot(self.root, task.id)
        if snapshot is None:
            raise UsageError(
                f"{task.id} has no attempt snapshot, so its changes cannot be told from the "
                "state it started in",
                hint=f"Run `aipm task reset {task.id}`, then `aipm prompt {task.id}`.",
            )
        return tasks, task, snapshot, state

    def run(self) -> VerifyResult:
        tasks, task, snapshot, state = self._task()
        # The base comes from the snapshot outside the repository, never from tasks.yaml, and
        # `--base` is resolved only once the integrity hashes allow git to run (SECURITY §11).
        moved = git.compare(snapshot.integrity, git.integrity_snapshot(self.root, Path.home()))
        base = (
            git.resolve_commit(self.root, self.options.base)
            if self.options.base and not moved
            else snapshot.base_sha
        )
        policy = check_policy(self.cfg)
        changes = changes_since(self.root, snapshot, base, self.cfg)
        violations = check_changes(changes, task, policy)
        result = VerifyResult(
            task=task.id, outcome="failed", run_id=new_run_id(), attempt=task.attempts + 1,
            base_sha=base, report=GateReport(task=task.id), violations=violations,
            sandboxed=self.sandbox is not None, warnings=self.warnings,
        )  # fmt: skip
        if severe(violations):
            self._block(tasks, task, result, violations, None)
        # Tampering is judged first; only then must the plan be the approved, current one (G3).
        self.warnings += require_inputs(
            self.store, "verify", prompt_inputs(state), accept_stale=self.options.accept_stale
        )
        ctx = GateContext(
            ws=GateWorkspace(root=self.root, temp_dir=self.temp, base_sha=base),
            task=task, cfg=self.cfg, changes=changes, redactor=self.store.redactor,
            home=Path.home(), now=datetime.now(UTC), runtime=self.sandbox,
        )  # fmt: skip
        reviewer, unavailable = _reviewer(self.cfg, self.store, no_cache=self.options.no_cache)
        scanned = _hashes(self.root, changes)
        gate_run = run_gates(
            ctx,
            reviewer=reviewer,
            reviewer_unavailable=unavailable,
            only=self.options.gate,
            override_ac=self.options.override_ac,
        )
        self.warnings += ctx.warnings
        after = check_changes(changes_since(self.root, snapshot, base, self.cfg), task, policy)
        late = [v for v in severe(after) if v not in violations]
        if late:
            self._block(tasks, task, result, [*violations, *late], gate_run)
        moved = [
            Violation(Kind.CHANGED_DURING_GATES, path, "changed while the gates ran")
            for path, digest in scanned.items()
            if git.hash_path(self.root / path) != digest
        ]
        result.violations = [*violations, *moved]
        return self._finish(tasks, task, result, gate_run, changes)

    def _block(
        self,
        tasks: TasksDoc,
        task: Task,
        result: VerifyResult,
        violations: list[Violation],
        gate_run: GateRun | None,
    ) -> None:
        result.outcome = "blocked"
        result.violations = violations
        earlier = gate_run.results if gate_run is not None else []
        gates = [checks_result(violations), *earlier][:32]
        result.report = GateReport(
            task=task.id, run_id=result.run_id, attempt=result.attempt, gates=gates
        )
        _record_violations(self.store, task, violations)
        first = severe(violations)[0]
        blocked = task.model_copy(
            update={
                "status": TaskStatus.BLOCKED,
                "attempts": result.attempt,
                "blocked": Blocked(
                    reason=BlockedReason.POLICY_VIOLATION,
                    detail=f"{first.kind.value}: {first.path}: {first.detail}"[:1000],
                ),
            }
        )
        events: Events = [
            (JournalEventType.POLICY_VIOLATION, {"kind": v.kind.value, "path": v.path[:512]})
            for v in severe(violations)[:MAX_EVENTS]
        ]
        events.append(
            (JournalEventType.TASK_BLOCKED,
             {"reason": "policy_violation", "after_gates": gate_run is not None})
        )  # fmt: skip
        _save_run(self.store, result, gate_run.outputs if gate_run else {}, events)
        _save_tasks(self.store, tasks, blocked)
        count = len(severe(violations))
        raise _stop(
            result,
            PolicyViolation,
            f"{task.id} is blocked: {count} severe post-change violation(s), the first "
            f"{first.kind.value} at {first.path}",
            f"Review the changes and `aipm status`, then `aipm task unblock {task.id}` or "
            f"`aipm task reset {task.id}`.",
        )

    def _finish(
        self,
        tasks: TasksDoc,
        task: Task,
        result: VerifyResult,
        gate_run: GateRun,
        changes: ChangeSet,
    ) -> VerifyResult:
        options = self.options
        minor = result.violations
        gates = ([checks_result(minor)] if minor else []) + gate_run.results
        result.report = GateReport(
            task=task.id, run_id=result.run_id, attempt=result.attempt, gates=gates[:32]
        )
        if gate_run.injection:
            self.store.append_event(
                SecurityEventKind.INJECTION_SIGNAL,
                source=f"llm:{RoleName.AC_REVIEWER.value}",
                detail=f"the AC reviewer reported {len(gate_run.injection)} suspected "
                f"instructions in the diff of {task.id}",
                data={"excerpts": list(gate_run.injection)},
            )
        if options.override_ac is not None:
            applied = options.override_ac in gate_run.overridden
            _record_override(self.store, task, options, result.run_id, applied=applied)
        held = bool(gate_run.injection) and not options.accept_risk
        done = gate_run.passed() and not minor and options.gate is None and not held
        events: Events = [(JournalEventType.CHECK_RESULT, {"violations": len(minor)})]
        for g in gate_run.results:
            data: dict[str, JsonValue] = {"gate": g.name, "status": g.status.value}
            events.append((JournalEventType.GATE_RESULT, data))
        update: dict[str, object] = {"attempts": result.attempt}
        if done:
            if options.commit:
                result.commit = self._commit(task, result, changes)
                events.append((JournalEventType.TASK_COMMITTED, {"commit": result.commit}))
            result.outcome = "done"
            finished = Done(commit=result.commit, run_id=result.run_id, at=datetime.now(UTC))
            update |= {"status": TaskStatus.DONE, "blocked": None, "done": finished}
        _save_run(self.store, result, gate_run.outputs, events)
        _save_tasks(self.store, tasks, task.model_copy(update=update))
        if done:
            return result
        raise self._failure(task, result, gate_run, held=held)

    def _failure(
        self, task: Task, result: VerifyResult, gate_run: GateRun, *, held: bool
    ) -> AipmError:
        if gate_run.missing_tools:
            names = ", ".join(gate_run.missing_tools)
            return _stop(
                result,
                MissingCapability,
                f"{task.id} cannot pass: required gate(s) {names} need a scanner that is not "
                "installed",
                "Install the scanner named in the gate summary, then verify again.",
            )
        if held:
            return _stop(
                result,
                HumanInputRequired,
                "the AC reviewer reported suspected prompt injection in the diff",
                "Review the diff. To accept the review anyway, verify again with --accept-risk.",
            )
        if self.options.gate is not None:
            reason = "--gate runs one gate and never marks a task done"
        else:
            reason = f"{task.id} did not pass verification"
        return _stop(
            result,
            VerificationFailed,
            reason,
            f"Fix it, for example with `aipm prompt {task.id} --fix`, then verify again.",
        )

    def _commit(self, task: Task, result: VerifyResult, changes: ChangeSet) -> str:
        paths = [c.path for c in changes.files if not c.path.startswith(".pm/")]
        if not paths:
            raise UsageError(f"{task.id} changed no file, so there is nothing to commit")
        title = " ".join(sanitize_text(task.title, source="task title").text.split())[:72]
        trailers = [
            ("Aipm-Task", task.id),
            ("Aipm-Run", result.run_id),
            ("Aipm-Attempt", str(result.attempt)),
        ]
        return git.commit(self.root, paths, message=f"aipm: {task.id} {title}", trailers=trailers)


def run(project: Path | None, options: VerifyOptions) -> VerifyResult:
    """Run the use case."""
    root = find_repo_root(project)
    require_initialized(root)
    loaded = load_config(root)
    cfg = loaded.config
    _check_options(options, cfg)
    require_trusted(root, loaded, command="verify")
    store = runtime.open_repo_store(root)
    temp = _attempt_dir(root)
    try:
        sandbox = resolve_sandbox(
            mode=cfg.dispatch.sandbox.value,
            require=cfg.security.require_sandbox,
            repo=root,
            temp_dir=temp,
        )
        warnings = [*loaded.warnings, *([sandbox.warning] if sandbox.warning else [])]
        with store.lock():
            return _Verify(root, cfg, store, options, temp, sandbox.launcher, warnings).run()
    finally:
        shutil.rmtree(temp, ignore_errors=True)
