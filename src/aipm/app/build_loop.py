"""The asyncio build orchestrator (C-18, ARCHITECTURE §12.3-§12.6).

One coroutine per running task; sync stages (git, the checks, the gates) run in worker threads,
the agent through `run_safe_async`. Every `.pm/` write (journal, tasks, run files, events)
happens on the event loop's thread. For each task, in a fresh worktree from the integration
branch's head:

1. integrity snapshot (and the hashes of the agent's config-home settings);
2. dispatch, sandboxed, with the task budget and the attempt timeout;
3. post-change checks: a severe violation blocks the task at once, never retried, and is a
   security event; a minor one is reverted and fails the attempt with feedback;
4. prepare and gates (fail-fast with `dispatch.fail_fast`), then the checks again;
5. pass: one commit with `Aipm-Task`/`Aipm-Run`/`Aipm-Attempt` trailers, checked against what
   was verified, then fast-forwarded (rebased first if needed) onto the integration branch;
6. fail: a fix prompt with the failures (untrusted) and `--resume`, until `--max-retries`.

`AIPM-BLOCKED:` only blocks the task; nothing else an agent says changes anything. The run
budget is checked before every dispatch, holding each running attempt's task budget. The first
Ctrl-C stops scheduling and gives running attempts 30 s, then SIGTERM and SIGKILL; a second
kills at once. Either way the journal gets `interrupted` and the run can be resumed.
"""

import asyncio
import json
import os
import shutil
import signal
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path

from pydantic import JsonValue

from aipm.adapters.base import DispatchLimits, ToolAdapter
from aipm.adapters.compiler import compile_task_spec, render_within_budget
from aipm.app.attempt import (
    MAX_EVENTS,
    attempt_dir,
    base_ignores,
    changed_hashes,
    check_policy,
    checks_result,
    moved_since,
    new_run_id,
    prepare_hold,
    record_violations,
    reviewer,
)
from aipm.app.dispatcher import Dispatch, Isolation, config_home_hashes, dispatch
from aipm.app.repo_map import ignore_spec
from aipm.config.schema import Config
from aipm.domain.errors import AipmError, BudgetExceeded, PolicyViolation
from aipm.domain.models import (
    Blocked,
    BlockedReason,
    ChangeSet,
    Done,
    GateReport,
    GateResult,
    GateStatus,
    GateWorkspace,
    JournalEventType,
    ProjectContext,
    SecurityEventKind,
    Task,
    TasksDoc,
    TaskStatus,
    ToolName,
    Workspace,
)
from aipm.domain.scheduler import next_batch, ready
from aipm.execution import git, process
from aipm.execution.git import MAX_CONTENT_BYTES, ChangeInputs
from aipm.execution.journal import Journal, find_resumable, load, replay
from aipm.execution.process import KILL_GRACE_S
from aipm.execution.sandbox import Runtime
from aipm.execution.worktree import (
    AGENT_HOMES_DIR,
    WorktreeManager,
    cache_root,
    ensure_integration,
    find_task_commit,
    integrate,
    outside_repo,
    task_branch,
)
from aipm.gates.context import GateContext
from aipm.gates.runner import GateRun, run_gates
from aipm.reporting.worksheet import WORKSHEET_FILE, render_worksheet
from aipm.security.budget import RunBudget, Spend, TokenCounter, attempt_cost
from aipm.security.diff_checks import (
    Kind,
    Violation,
    check_changes,
    content_limit,
    is_watched,
    needs_content,
    severe,
)
from aipm.security.sanitize import sanitize_text
from aipm.state.layout import repo_id
from aipm.state.store import FileStateStore
from aipm.state.yamlio import dump_yaml

GRACE_S = 30.0
STOP_SIGNALS = (signal.SIGINT, signal.SIGTERM, signal.SIGHUP)
"""How long running attempts may go on after the first Ctrl-C (ARCHITECTURE §12.6)."""


@dataclass(frozen=True, slots=True)
class Progress:
    """One line of live progress: a task's state (`queued`, `worktree`, `agent`, `checks`,
    `gates`, `commit`, `done`, `blocked`, `interrupted`), or a `warning` for every dispatch
    without a sandbox. `detail` is aipm's words, or sanitized agent text."""

    task: str
    state: str
    attempt: int | None = None
    spent_usd: float = 0.0
    detail: str | None = None


type ProgressSink = Callable[[Progress], None]


@dataclass(slots=True)
class TaskOutcome:
    """How one task left this run."""

    task: str
    status: str
    attempts: int = 0
    reason: str | None = None
    detail: str | None = None
    question: str | None = None
    commit: str | None = None

    def to_data(self) -> dict[str, object]:
        """The `--json` form."""
        return {
            "task": self.task,
            "status": self.status,
            "attempts": self.attempts,
            "reason": self.reason,
            "detail": self.detail,
            "question": self.question,
            "commit": self.commit,
        }


@dataclass(slots=True)
class BuildSummary:
    """What a build did (the end-of-run summary)."""

    run_id: str
    resumed: bool
    integration: str
    outcomes: list[TaskOutcome]
    spent_usd: float
    run_usd: float
    budget_exceeded: bool = False
    interrupted: bool = False
    severe: bool = False
    warnings: list[str] = field(default_factory=list[str])

    @property
    def blocked(self) -> list[TaskOutcome]:
        """The tasks this run blocked."""
        return [o for o in self.outcomes if o.status == "blocked"]

    def to_data(self) -> dict[str, object]:
        """The `--json` payload."""
        return {
            "run_id": self.run_id,
            "resumed": self.resumed,
            "integration": self.integration,
            "tasks": [o.to_data() for o in self.outcomes],
            "spent_usd": round(self.spent_usd, 4),
            "run_usd": self.run_usd,
            "budget_exceeded": self.budget_exceeded,
            "interrupted": self.interrupted,
            "severe": self.severe,
            "warnings": list(self.warnings),
        }


@dataclass(frozen=True, slots=True)
class BuildSettings:
    """Everything a build decided before it starts."""

    root: Path
    cfg: Config
    kind: str
    parallel: int
    max_retries: int
    timeout_s: float
    budget: RunBudget
    only: frozenset[str] | None
    approval: str
    integration: str
    no_cache: bool = False


@dataclass(slots=True)
class _Attempted:
    """What one attempt left for the next: the report to fix, and the agent session."""

    passed: bool
    stop: bool = False
    report: GateReport | None = None
    session: str | None = None
    session_total: float = 0.0
    timed_out: bool = False
    cost: float = 0.0


def _clean(text: str, limit: int) -> str:
    return " ".join(sanitize_text(text, source="build").text.split())[:limit]


def _agent_summary(d: Dispatch) -> str:
    if d.process.timed_out:
        return "the agent ran out of time and was stopped"
    if d.result.subtype and d.result.subtype != "success":
        return f"the agent stopped: {d.result.subtype}"
    if d.result.is_error:
        return "the agent reported an error"
    return f"the agent exited with code {d.process.returncode}"


class BuildLoop:
    """One build or run, under the `.pm/` lock held by the caller."""

    def __init__(
        self,
        settings: BuildSettings,
        *,
        store: FileStateStore,
        tasks: TasksDoc,
        ctx: ProjectContext,
        context_text: str,
        adapter: ToolAdapter,
        runtime: Runtime | None,
        progress: ProgressSink | None = None,
        sandbox_warning: str | None = None,
    ) -> None:
        self.s = settings
        self.cfg = settings.cfg
        self.root = settings.root
        self.store = store
        self.doc = tasks
        self.tasks: dict[str, Task] = {t.id: t for t in tasks.tasks}
        self.ctx = ctx
        self.context_text = context_text
        self.adapter = adapter
        self.runtime = runtime
        self.sink = progress
        self.sandbox_warning = sandbox_warning
        self.home = Path.home()
        self.policy = check_policy(self.cfg)
        self.serialized = tuple(self.cfg.plan.serialized_paths)
        self.worktrees = WorktreeManager(self.root)
        self.spend = Spend(settings.budget)
        self.tokens = TokenCounter(settings.budget.run_tokens)
        self.claude = self.cfg.dispatch.tools.get(ToolName.CLAUDE)
        self.run_id = ""
        self.run_base: str | None = None
        self.journal: Journal | None = None
        self.agent_root = Path()
        self.homes: dict[str, Path] = {}
        self.resumed = False
        self.resumable: set[str] = set()
        self.run_attempts: dict[str, int] = {}
        self.finished: set[str] = set()
        self.outcomes: dict[str, TaskOutcome] = {}
        self.cost_by_task: dict[str, float] = {}
        self.warnings: list[str] = []
        self.running: dict[str, asyncio.Task[None]] = {}
        self.stopping = False
        self.interrupted = False
        self.budget_hit = False
        self.severe = False
        self._merge_lock: asyncio.Lock | None = None
        self._grace: asyncio.Task[None] | None = None

    # ------------------------------------------------------------ entry

    def run(self) -> BuildSummary:
        """Run the build to its end; the summary says how it went."""
        return asyncio.run(self._main())

    async def _main(self) -> BuildSummary:
        loop = asyncio.get_running_loop()
        self._merge_lock = asyncio.Lock()
        installed = self._install_signals(loop)
        try:
            await self._start()
            await self._schedule()
        finally:
            if installed:
                for sig in STOP_SIGNALS:
                    loop.remove_signal_handler(sig)
            self._finish()
        return self._summary()

    def _install_signals(self, loop: asyncio.AbstractEventLoop) -> bool:
        """Ctrl-C, and SIGTERM or SIGHUP from a supervisor or a closed terminal, stop the build
        the same way: agents and gates run in their own sessions and would outlive aipm."""
        try:
            for sig in STOP_SIGNALS:
                loop.add_signal_handler(sig, self._on_interrupt)
        except (NotImplementedError, RuntimeError, ValueError):
            return False
        return True

    def _on_interrupt(self) -> None:
        if not self.stopping:
            self.stopping = True
            self._emit("*", "interrupted", detail="stopping: running tasks get 30 s to finish")
            self._grace = asyncio.get_running_loop().create_task(self._wind_down())
            return
        self.interrupted = True
        process.signal_running(signal.SIGKILL)
        for task in self.running.values():
            task.cancel()

    async def _wind_down(self) -> None:
        pending = set(self.running.values())
        if pending:
            _, pending = await asyncio.wait(pending, timeout=GRACE_S)
        if pending:
            self.interrupted = True
            process.signal_running(signal.SIGTERM)
            _, pending = await asyncio.wait(pending, timeout=KILL_GRACE_S)
            if pending:
                process.signal_running(signal.SIGKILL)

    # ------------------------------------------------------------ journal and state

    def _journal(
        self,
        event: JournalEventType,
        task: str | None = None,
        attempt: int | None = None,
        **data: JsonValue,
    ) -> None:
        if self.journal is not None:
            self.journal.append(event, task=task, attempt=attempt, data=data)

    def _emit(
        self, task: str, state: str, attempt: int | None = None, detail: str | None = None
    ) -> None:
        if self.sink is not None:
            self.sink(Progress(task, state, attempt, self.spend.spent_usd, detail))

    def _save(self, task: Task) -> None:
        self.tasks[task.id] = task
        self.doc = self.doc.model_copy(update={"tasks": [self.tasks[t.id] for t in self.doc.tasks]})
        self.store.save(self.doc)
        self.store.write_text(WORKSHEET_FILE, render_worksheet(self.doc))

    def _run_text(self, parts: list[str], text: str) -> str | None:
        try:
            return self.store.save_run_text(self.run_id, parts, text)
        except PolicyViolation:
            # A secret survived redaction: keep the record, not the text.
            return self.store.save_run_text(
                self.run_id, parts, "(withheld: it held a secret aipm could not redact)\n"
            )

    def _write_cost(self) -> None:
        budget = self.s.budget
        data = {
            "run_id": self.run_id,
            "spent_usd": round(self.spend.spent_usd, 6),
            "run_usd": budget.run_usd,
            "task_usd": budget.task_usd,
            "tasks": {k: round(v, 6) for k, v in sorted(self.cost_by_task.items())},
            "tokens_used": self.tokens.used,
            "run_tokens": budget.run_tokens,
        }
        self._run_text(["cost.json"], json.dumps(data, indent=2) + "\n")

    def _outcome(self, task_id: str, status: str, **kw: object) -> None:
        attempts = self.tasks[task_id].attempts
        self.outcomes[task_id] = TaskOutcome(task_id, status, attempts, **kw)  # type: ignore[arg-type]

    def _block(
        self, task_id: str, reason: BlockedReason, detail: str, question: str | None = None
    ) -> None:
        task = self.tasks[task_id]
        clean = _clean(detail, 1000)
        blocked = Blocked(reason=reason, detail=clean, question=question)
        self._save(task.model_copy(update={"status": TaskStatus.BLOCKED, "blocked": blocked}))
        self._journal(
            JournalEventType.TASK_BLOCKED,
            task_id,
            task.attempts,
            reason=reason.value,
            detail=clean[:500],
        )
        self._outcome(task_id, "blocked", reason=reason.value, detail=clean, question=question)
        self._emit(task_id, "blocked", task.attempts, f"{reason.value}: {clean[:200]}")

    def _done(self, task_id: str, commit: str | None) -> None:
        task = self.tasks[task_id]
        finished = Done(commit=commit, run_id=self.run_id, at=datetime.now(UTC))
        update = {"status": TaskStatus.DONE, "blocked": None, "done": finished}
        self._save(task.model_copy(update=update))
        self._outcome(task_id, "done", commit=commit)
        self._emit(task_id, "done", task.attempts, None if commit is None else commit[:12])

    def _budget_stop(self) -> None:
        if not self.budget_hit:
            self.budget_hit = True
            self._journal(
                JournalEventType.BUDGET_EXCEEDED,
                spent_usd=round(self.spend.spent_usd, 6),
                run_usd=self.s.budget.run_usd,
            )
            self._emit("*", "warning", detail="the run budget is spent: no new dispatch")

    # ------------------------------------------------------------ start, resume, finish

    async def _start(self) -> None:
        integration = await asyncio.to_thread(ensure_integration, self.root, self.s.integration)
        if integration.diverged:
            self.warnings.append(
                f"{self.s.integration} and your branch have diverged; tasks build on "
                f"{self.s.integration}, and `aipm merge` will need you to merge by hand"
            )
        found = find_resumable(self.store)
        events = load(self.store, found) if found else None
        state = replay(found, events) if found and events else None
        if found and state is not None and state.integration == self.s.integration:
            self.run_id = found
            self.resumed = True
            self.journal = Journal(self.store, found, seq=state.next_seq)
            self.run_base = state.base
            self.spend.spent_usd = state.spent_usd
            self._home_dir()
            for task_id, seen in state.tasks.items():
                await self._reconcile(task_id, seen.committed, seen.dispatches)
            return
        self.run_id = new_run_id()
        self.journal = Journal(self.store, self.run_id)
        self.run_base = integration.head
        self._home_dir()
        self._journal(
            JournalEventType.RUN_STARTED,
            kind=self.s.kind,
            integration=self.s.integration,
            base=integration.head,
            parallel=self.s.parallel,
            max_retries=self.s.max_retries,
            run_usd=self.s.budget.run_usd,
            task_usd=self.s.budget.task_usd,
            only=",".join(sorted(self.s.only)) if self.s.only is not None else None,
        )

    def _home_dir(self) -> None:
        base = cache_root() / AGENT_HOMES_DIR / repo_id(self.root) / self.run_id
        self.agent_root = outside_repo(base, self.root, "the agents' config homes")
        self.agent_root.mkdir(mode=0o700, parents=True, exist_ok=True)

    def _fresh_home(self, task_id: str) -> Path:
        """The task's own config home, empty: one per task, so no agent sees settings another
        planted, and a resumed task starts from nothing (step 07 review)."""
        home = self.agent_root / task_id / "claude"
        shutil.rmtree(home, ignore_errors=True)
        home.mkdir(mode=0o700, parents=True)
        self.homes[task_id] = home
        return home

    async def _reconcile(self, task_id: str, committed: str | None, dispatches: int) -> None:
        """Resume one task of the interrupted run (ARCHITECTURE §12.6)."""
        task = self.tasks.get(task_id)
        if task is None or task.status is not TaskStatus.IN_PROGRESS:
            return
        merged = await asyncio.to_thread(
            find_task_commit,
            self.root,
            self.s.integration,
            task=task_id,
            run=self.run_id,
            since=self.run_base,
        )
        if merged is not None:
            self._journal(
                JournalEventType.TASK_MERGED, task_id, task.attempts, commit=merged, resumed=True
            )
            self._done(task_id, merged)
            self.finished.add(task_id)
            await asyncio.to_thread(self._cleanup, task_id)
            return
        wt = self.worktrees.path(task_id)
        if committed is not None and (wt / ".git").is_file():
            head = await asyncio.to_thread(git.head_sha, wt)
            base = task.base_sha
            if head == committed and base is not None:
                await self._merge(task_id, wt, base, committed)
                self.finished.add(task_id)
                return
        self.resumable.add(task_id)
        self.run_attempts[task_id] = dispatches

    def _cleanup(self, task_id: str) -> None:
        self.worktrees.remove(task_id)
        branch = task_branch(task_id)
        sha = git.ref_sha(self.root, branch)
        if sha is not None:
            git.delete_branch(self.root, branch, sha)

    def _finish(self) -> None:
        if self.journal is None:
            return
        if self.stopping or self.interrupted:
            for task_id in sorted(
                set(self.running) | {t for t in self.resumable if t not in self.finished}
            ):
                if task_id not in self.outcomes:
                    self._outcome(task_id, "interrupted")
            self._journal(JournalEventType.INTERRUPTED, spent_usd=round(self.spend.spent_usd, 6))
        else:
            self._journal(JournalEventType.RUN_FINISHED, spent_usd=round(self.spend.spent_usd, 6))
            shutil.rmtree(self.agent_root, ignore_errors=True)
        self._write_cost()

    def _summary(self) -> BuildSummary:
        return BuildSummary(
            run_id=self.run_id,
            resumed=self.resumed,
            integration=self.s.integration,
            outcomes=[self.outcomes[k] for k in sorted(self.outcomes)],
            spent_usd=self.spend.spent_usd,
            run_usd=self.s.budget.run_usd,
            budget_exceeded=self.budget_hit,
            interrupted=self.stopping or self.interrupted,
            severe=self.severe,
            warnings=self.warnings,
        )

    # ------------------------------------------------------------ scheduling

    async def _schedule(self) -> None:
        while True:
            if not self.stopping and not self.budget_hit:
                self._start_ready()
            if not self.running:
                return
            done, _ = await asyncio.wait(
                set(self.running.values()), return_when=asyncio.FIRST_COMPLETED
            )
            for finished in done:
                self.running.pop(finished.get_name(), None)
                if not finished.cancelled() and finished.exception() is not None:
                    self.stopping = True
                    for other in self.running.values():
                        other.cancel()
                    raise cast_exception(finished.exception())

    def _start_ready(self) -> None:
        busy = [self.tasks[t] for t in self.running]
        candidates = [
            t
            for t in ready(self.tasks.values(), resumable=self.resumable, only=self.s.only)
            if t.id not in self.running and t.id not in self.finished
        ]
        slots = self.s.parallel - len(self.running)
        for task in next_batch(candidates, running=busy, slots=slots, serialized=self.serialized):
            if not self.spend.may_dispatch():
                self._budget_stop()
                return
            self._emit(task.id, "queued", task.attempts + 1)
            self.running[task.id] = asyncio.create_task(self._task(task.id), name=task.id)

    async def _task(self, task_id: str) -> None:
        try:
            await self._attempts(task_id)
        except BudgetExceeded as exc:
            self._budget_stop()
            self._block(task_id, BlockedReason.BUDGET_EXCEEDED, exc.message)
        except PolicyViolation as exc:
            self.severe = True
            self.store.append_event(
                SecurityEventKind.POLICY_VIOLATION,
                source=f"build:{task_id}",
                detail=exc.message[:1000],
            )
            self._block(task_id, BlockedReason.POLICY_VIOLATION, exc.message)
        except AipmError as exc:
            self._block(task_id, BlockedReason.MANUAL, f"aipm stopped this task: {exc.message}")
        finally:
            self.finished.add(task_id)

    # ------------------------------------------------------------ one task

    async def _attempts(self, task_id: str) -> None:
        task = self.tasks[task_id]
        base = git.ref_sha(self.root, self.s.integration)
        if base is None:
            raise PolicyViolation(f"the integration branch {self.s.integration} is gone")
        self._emit(task_id, "worktree", task.attempts + 1)
        wt = await asyncio.to_thread(self.worktrees.create, task_id, base)
        self._journal(
            JournalEventType.TASK_SCHEDULED,
            task_id,
            task.attempts + 1,
            base=base,
            resumed=task_id in self.resumable,
        )
        self._journal(JournalEventType.WORKTREE_CREATED, task_id, task.attempts + 1, base=base)
        self._save(
            task.model_copy(
                update={"status": TaskStatus.IN_PROGRESS, "base_sha": base, "blocked": None}
            )
        )
        integrity = await asyncio.to_thread(git.integrity_snapshot, wt, self.home)
        agent_before = config_home_hashes(await asyncio.to_thread(self._fresh_home, task_id))
        last = _Attempted(passed=False)
        while True:
            if self.stopping:
                self._outcome(task_id, "interrupted")
                return
            count = self.run_attempts.get(task_id, 0)
            if count >= max(self.s.max_retries, 1):
                self._exhausted(task_id, last)
                return
            if not self.spend.may_dispatch():
                self._budget_stop()
                self._block(
                    task_id,
                    BlockedReason.BUDGET_EXCEEDED,
                    "the run budget was spent before this task passed",
                )
                return
            last = await self._attempt(task_id, wt, base, integrity, agent_before, last)
            if last.passed or last.stop:
                return

    def _exhausted(self, task_id: str, last: _Attempted) -> None:
        failing = [] if last.report is None else [g.name for g in last.report.failures()]
        if last.timed_out:
            self._block(
                task_id, BlockedReason.TIMEOUT, "the agent ran out of time on its last attempt"
            )
            return
        names = ", ".join(failing) or "none recorded"
        self._block(
            task_id,
            BlockedReason.GATES_FAILED,
            f"no attempt passed in {self.s.max_retries}; failing: {names}",
        )

    def _changes(self, wt: Path, base: str, integrity: dict[str, str | None]) -> ChangeSet:
        policy = self.policy
        inputs = ChangeInputs(
            base_sha=base,
            integrity=integrity,
            files={},
            ledger={},
            extra_protected=policy.extra_protected,
        )
        return git.change_set(
            wt,
            inputs,
            home=self.home,
            watch_ignored=lambda p: is_watched(p, policy),
            wants_content=lambda p: needs_content(p, policy.test_roots),
            content_limit=lambda p: content_limit(p, MAX_CONTENT_BYTES),
        )

    def _limits(self, verify: tuple[tuple[str, ...] | None, ...]) -> DispatchLimits:
        claude = self.claude
        return DispatchLimits(
            timeout_s=self.s.timeout_s,
            task_usd=self.s.budget.task_usd,
            allowed_commands=tuple(p for p in verify if p),
            pass_env=tuple(claude.pass_env) if claude else (),
            allow_auto_mode=claude.allow_auto_mode if claude else False,
            bare=claude.bare if claude else True,
        )

    async def _attempt(
        self,
        task_id: str,
        wt: Path,
        base: str,
        integrity: dict[str, str | None],
        agent_before: dict[str, str | None],
        last: _Attempted,
    ) -> _Attempted:
        task = self.tasks[task_id]
        number = task.attempts + 1
        key = f"{task_id}/{number}"
        self.spend.reserve(key)
        self.run_attempts[task_id] = self.run_attempts.get(task_id, 0) + 1
        temp = await asyncio.to_thread(attempt_dir, self.root, "aipm-attempt-")
        try:
            dirs = {name: temp / name for name in ("agent", "context", "gates")}
            for path in dirs.values():
                path.mkdir(mode=0o700)
            spec = compile_task_spec(task, self.ctx, previous=last.report, approval=self.s.approval)
            prompt = render_within_budget(self.adapter, spec, self.ctx)
            self._run_text(["prompts", f"{task_id}.{number}.md"], prompt.text)
            self._journal(
                JournalEventType.PROMPT_COMPILED,
                task_id,
                number,
                bytes=prompt.size,
                fix=last.report is not None,
            )
            ws = Workspace(
                root=wt,
                temp_dir=dirs["agent"],
                context_dir=dirs["context"],
                config_home=self.homes[task_id],
                context_text=self.context_text,
                resume_session=last.session,
            )
            isolation = Isolation(
                runtime=self.runtime,
                home=self.home,
                main_pm=self.root / ".pm",
                other_worktrees=self.worktrees.others(task_id),
                network=self.cfg.security.network.agent,
            )
            if self.sandbox_warning is not None:
                self._emit(task_id, "warning", number, self.sandbox_warning)
            self._journal(
                JournalEventType.AGENT_STARTED,
                task_id,
                number,
                resume=last.session is not None,
                sandboxed=self.runtime is not None,
            )
            self._emit(task_id, "agent", number)
            try:
                done = await dispatch(
                    self.adapter,
                    prompt,
                    self._limits(tuple(g.allow_prefix for g in spec.verify)),
                    ws,
                    isolation,
                )
            except PolicyViolation as exc:
                self.spend.settle(key, 0.0)
                self.store.append_event(
                    SecurityEventKind.FORBIDDEN_FLAG,
                    source=f"build:{task_id}",
                    detail=exc.message[:1000],
                )
                raise
            return await self._after_agent(
                task_id, number, key, wt, base, integrity, agent_before, last, done, dirs["gates"]
            )
        finally:
            await asyncio.to_thread(shutil.rmtree, temp, True)

    def _settle(self, task_id: str, key: str, done: Dispatch, last: _Attempted) -> _Attempted:
        result = done.result
        same = last.session is not None and result.session_id == last.session
        cost = attempt_cost(
            reported_total=result.cost_usd if result.saw_result else None,
            previous_total=last.session_total if same else 0.0,
            cap=self.s.budget.task_usd,
        )
        self.spend.settle(key, cost)
        self.cost_by_task[task_id] = self.cost_by_task.get(task_id, 0.0) + cost
        session, total = last.session, last.session_total
        if result.saw_result and result.session_id and result.cost_usd is not None:
            session, total = result.session_id, result.cost_usd
        return _Attempted(
            passed=False, session=session, session_total=total, timed_out=done.process.timed_out,
            cost=cost,
        )  # fmt: skip

    def _save_agent(self, task_id: str, number: int, done: Dispatch) -> None:
        base = ["agent", task_id, str(number)]
        self._run_text([*base, "stdout.jsonl"], done.process.stdout.decode("utf-8", "replace"))
        self._run_text([*base, "stderr.txt"], done.process.stderr.decode("utf-8", "replace"))
        result = done.result
        summary = {
            "exit_code": result.exit_code,
            "timed_out": result.timed_out,
            "saw_result": result.saw_result,
            "is_error": result.is_error,
            "subtype": result.subtype,
            "cost_usd": result.cost_usd,
            "session_id": result.session_id,
            "blocked_question": result.blocked_question,
            "output_dropped_bytes": done.process.dropped_bytes,
        }
        self._run_text([*base, "result.json"], json.dumps(summary, indent=2) + "\n")

    async def _after_agent(
        self,
        task_id: str,
        number: int,
        key: str,
        wt: Path,
        base: str,
        integrity: dict[str, str | None],
        agent_before: dict[str, str | None],
        last: _Attempted,
        done: Dispatch,
        gates_dir: Path,
    ) -> _Attempted:
        attempted = self._settle(task_id, key, done, last)
        self._save_agent(task_id, number, done)
        result = done.result
        self._journal(
            JournalEventType.AGENT_FINISHED,
            task_id,
            number,
            exit_code=result.exit_code,
            timed_out=result.timed_out,
            saw_result=result.saw_result,
            is_error=result.is_error,
            subtype=result.subtype,
            cost_usd=round(attempted.cost, 6),
        )
        self._write_cost()
        if self.interrupted:
            return _Attempted(passed=False, stop=True)
        self._emit(task_id, "checks", number)
        changes = await asyncio.to_thread(self._changes, wt, base, integrity)
        violations = check_changes(changes, self.tasks[task_id], self.policy)
        if config_home_hashes(self.homes[task_id]) != agent_before:
            violations.append(
                Violation(
                    Kind.GIT_INTEGRITY,
                    "CLAUDE_CONFIG_DIR",
                    "the agent changed the settings, hooks or skills in its config home",
                )
            )
        self._journal(
            JournalEventType.CHECK_RESULT,
            task_id,
            number,
            violations=len(violations),
            severe=len(severe(violations)),
        )
        if severe(violations):
            self._severe(task_id, number, violations, None)
            return _Attempted(passed=False, stop=True)
        if result.blocked_question is not None:
            self._count(task_id, number)
            self._block(
                task_id,
                BlockedReason.AGENT_BLOCKED,
                "the agent asked a question",
                question=result.blocked_question,
            )
            return _Attempted(passed=False, stop=True)
        minor = list(violations)
        if minor:
            paths = sorted({v.path for v in minor if not v.path.startswith(".pm/")})
            await asyncio.to_thread(git.restore_paths, wt, base, paths)
            changes = await asyncio.to_thread(self._changes, wt, base, integrity)
        agent_ok = (
            done.process.returncode == 0 and not done.process.timed_out and not result.is_error
        )
        results: list[GateResult] = [checks_result(minor)] if minor else []
        outputs: dict[str, str] = {}
        passed = False
        commit_paths: list[str] = []
        expected: dict[str, git.StagedId] = {}
        if not agent_ok:
            results.append(
                GateResult(
                    name="agent",
                    status=GateStatus.ERROR,
                    required=True,
                    summary=_agent_summary(done),
                )
            )
        else:
            commit_paths = [c.path for c in changes.files if not c.path.startswith(".pm/")]
            if not commit_paths:
                results.append(
                    GateResult(
                        name="changes",
                        status=GateStatus.FAIL,
                        required=True,
                        summary="the attempt changed no file",
                    )
                )
            else:
                self._emit(task_id, "gates", number)
                expected = await asyncio.to_thread(git.staged_ids, wt, commit_paths)
                gated = await self._gates(task_id, wt, base, integrity, changes, minor, gates_dir)
                if gated is None:
                    return _Attempted(passed=False, stop=True)
                gate_run, moved = gated
                outputs = gate_run.outputs
                results += ([checks_result(moved)] if moved else []) + gate_run.results
                passed = gate_run.passed() and not minor and not moved
        report = GateReport(task=task_id, run_id=self.run_id, attempt=number, gates=results[:32])
        self._save_report(task_id, number, report, outputs)
        self._count(task_id, number)
        if passed:
            self._emit(task_id, "commit", number)
            await self._commit(task_id, number, wt, base, commit_paths, expected)
            return _Attempted(passed=True)
        attempted.report = report
        return attempted

    async def _gates(
        self,
        task_id: str,
        wt: Path,
        base: str,
        integrity: dict[str, str | None],
        changes: ChangeSet,
        minor: list[Violation],
        gates_dir: Path,
    ) -> tuple[GateRun, list[Violation]] | None:
        """Prepare and gates, then the checks again. `None` when the task was blocked or the
        build interrupted meanwhile."""
        task = self.tasks[task_id]
        scanned = changed_hashes(wt, changes)
        ignores = await asyncio.to_thread(base_ignores, wt, base)
        review, unavailable = reviewer(
            self.cfg, self.store, no_cache=self.s.no_cache, tokens=self.tokens
        )
        gctx = GateContext(
            ws=GateWorkspace(root=wt, temp_dir=gates_dir, base_sha=base),
            task=task,
            cfg=self.cfg,
            changes=changes,
            redactor=self.store.redactor,
            home=self.home,
            now=datetime.now(UTC),
            runtime=self.runtime,
            withheld=ignore_spec(wt, also=ignores).match_file,
            changed_during_gates=lambda: moved_since(wt, scanned),
            deny_read=(self.homes[task_id],),
        )
        gate_run = await asyncio.to_thread(
            lambda: run_gates(
                gctx,
                reviewer=review,
                reviewer_unavailable=unavailable,
                hold_prepare=prepare_hold(minor),
                fail_fast=self.cfg.dispatch.fail_fast,
            )
        )
        if self.interrupted:
            return None
        for result in gate_run.results:
            self._journal(
                JournalEventType.GATE_RESULT,
                task_id,
                task.attempts + 1,
                gate=result.name,
                status=result.status.value,
                duration_ms=result.duration_ms,
            )
        after = await asyncio.to_thread(self._changes, wt, base, integrity)
        late = severe(check_changes(after, task, self.policy))
        if late:
            self._severe(task_id, task.attempts + 1, [*minor, *late], gate_run)
            return None
        if gate_run.injection:
            self.store.append_event(
                SecurityEventKind.INJECTION_SIGNAL,
                source="llm:ac_reviewer",
                detail=f"the AC reviewer reported {len(gate_run.injection)} suspected "
                f"instructions in the diff of {task_id}",
                data={"excerpts": list(gate_run.injection)},
            )
            self._count(task_id, task.attempts + 1)
            self._block(
                task_id,
                BlockedReason.POLICY_VIOLATION,
                "the AC reviewer reported suspected prompt injection in the diff; "
                "review it, then unblock or reset the task",
            )
            return None
        moved = [
            Violation(Kind.CHANGED_DURING_GATES, path, "changed while the gates ran")
            for path in moved_since(wt, scanned)
        ]
        return gate_run, moved

    def _count(self, task_id: str, number: int) -> None:
        task = self.tasks[task_id]
        if task.attempts < number:
            self._save(task.model_copy(update={"attempts": number}))

    def _save_report(
        self, task_id: str, number: int, report: GateReport, outputs: dict[str, str]
    ) -> None:
        base = ["gates", task_id, str(number)]
        refs: dict[str, str] = {}
        for name, text in outputs.items():
            if text:
                saved = self._run_text([*base, f"{name}.log"], text)
                if saved is not None:
                    refs[name] = saved
        gates = [g.model_copy(update={"output_ref": refs.get(g.name)}) for g in report.gates]
        self._run_text(
            [*base, "report.yaml"],
            dump_yaml(report.model_copy(update={"gates": gates}).model_dump(mode="json")),
        )

    def _severe(
        self, task_id: str, number: int, violations: list[Violation], gate_run: GateRun | None
    ) -> None:
        self.severe = True
        task = self.tasks[task_id]
        record_violations(self.store, task, violations, source="build")
        for v in severe(violations)[:MAX_EVENTS]:
            self._journal(
                JournalEventType.POLICY_VIOLATION,
                task_id,
                number,
                kind=v.kind.value,
                path=v.path[:512],
            )
        earlier = gate_run.results if gate_run is not None else []
        report = GateReport(
            task=task_id,
            run_id=self.run_id,
            attempt=number,
            gates=[checks_result(violations), *earlier][:32],
        )
        self._save_report(task_id, number, report, gate_run.outputs if gate_run else {})
        self._count(task_id, number)
        first = severe(violations)[0]
        self._block(
            task_id,
            BlockedReason.POLICY_VIOLATION,
            f"{first.kind.value}: {first.path}: {first.detail}",
        )

    # ------------------------------------------------------------ commit and merge

    async def _commit(
        self,
        task_id: str,
        number: int,
        wt: Path,
        base: str,
        paths: list[str],
        expected: dict[str, git.StagedId],
    ) -> None:
        existing = await asyncio.to_thread(
            find_task_commit,
            self.root,
            self.s.integration,
            task=task_id,
            run=self.run_id,
            since=self.run_base,
            attempt=number,
        )
        if existing is not None:
            self._journal(JournalEventType.TASK_MERGED, task_id, number, commit=existing)
            self._done(task_id, existing)
            await asyncio.to_thread(self._cleanup, task_id)
            return
        task = self.tasks[task_id]
        title = _clean(task.title, 72)
        trailers = [
            ("Aipm-Task", task_id),
            ("Aipm-Run", self.run_id),
            ("Aipm-Attempt", str(number)),
        ]
        commit = await asyncio.to_thread(
            lambda: git.commit(wt, paths, message=f"aipm: {task_id} {title}", trailers=trailers)
        )
        wrong = await asyncio.to_thread(self._check_commit, wt, base, commit, paths, expected)
        if wrong:
            self._severe(task_id, number, wrong, None)
            return
        self._journal(JournalEventType.TASK_COMMITTED, task_id, number, commit=commit)
        await self._merge(task_id, wt, base, commit)

    def _check_commit(
        self, wt: Path, base: str, commit: str, paths: list[str], expected: dict[str, git.StagedId]
    ) -> list[Violation]:
        """The commit holds exactly what was verified, on the attempt's base (RT02-8)."""
        got = git.committed_ids(wt, commit, paths)
        wrong = [
            Violation(Kind.COMMIT_MISMATCH, p, "the commit does not hold what was verified")
            for p in sorted(expected)
            if got.get(p) != expected[p]
        ]
        found = git.trailer_commits(wt, commit, since=base, limit=2)
        if len(found) != 1 or found[0].parents != (base,):
            wrong.append(Violation(Kind.COMMIT_MISMATCH, commit[:12], "not one commit on the base"))
        if sorted(git.changed_paths(wt, base, commit)) != sorted(set(paths)):
            wrong.append(
                Violation(
                    Kind.COMMIT_MISMATCH,
                    commit[:12],
                    "the commit changes other paths than the verified ones",
                )
            )
        return wrong

    async def _merge(self, task_id: str, wt: Path, base: str, commit: str) -> None:
        lock = self._merge_lock
        assert lock is not None  # noqa: S101 - set in _main
        async with lock:
            merged = await asyncio.to_thread(
                integrate, self.root, wt, self.s.integration, commit, base
            )
        task = self.tasks[task_id]
        if merged is None:
            self._block(
                task_id,
                BlockedReason.MERGE_CONFLICT,
                f"its commit {commit[:12]} conflicts with {self.s.integration}",
            )
            return
        self._journal(JournalEventType.TASK_MERGED, task_id, task.attempts, commit=merged)
        self._done(task_id, merged)
        await asyncio.to_thread(self._cleanup, task_id)


def cast_exception(exc: BaseException | None) -> BaseException:
    """The exception a finished task raised (never `None` where it is called)."""
    return exc if exc is not None else RuntimeError("a build task failed without an exception")


def environment_key_set(name: str) -> bool:
    """Whether the environment holds a non-empty value for `name` (never its value)."""
    return bool(os.environ.get(name))
