"""`aipm build` and `aipm run`: dispatch ready tasks to a coding agent and verify each one (§12).

Preconditions, in this order (ARCHITECTURE §12.1): the options (exit 2), trust (6),
`dispatch.enabled` (2), the `.pm/` lock (7), an approved plan that is not stale (G3, or
`--accept-stale`, recorded; 2), a clean tree outside `.pm/` (2), the repository's git config
(6), the integration branch is aipm's own (6), the adapter's flags (8), the agent's API key (8),
the sandbox when it is required (8), and a budget.

`--dry-run` compiles every prompt and prints the batches and each argv; it dispatches nothing
and writes nothing. Exit codes after a build: 130 when interrupted, 6 after a severe violation,
5 when the budget stopped it, 3 when a task was blocked, else 0.
"""

import math
import os
import shutil
from dataclasses import dataclass, field
from pathlib import Path

from aipm.adapters.base import ToolAdapter
from aipm.adapters.compiler import compile_task_spec, render_within_budget
from aipm.adapters.registry import get_adapter, parse_tool
from aipm.app import runtime
from aipm.app.approve import require_inputs
from aipm.app.attempt import attempt_dir
from aipm.app.build_loop import BuildLoop, BuildSettings, BuildSummary, ProgressSink
from aipm.app.dispatcher import native_allowed, tool_limits
from aipm.app.project_context import build_context
from aipm.app.snapshot import read_snapshot
from aipm.app.trust import require_trusted
from aipm.app.workspace import find_repo_root, require_initialized
from aipm.config.loader import load_config
from aipm.config.schema import Config, duration_seconds
from aipm.domain.errors import (
    BudgetExceeded,
    Interrupted,
    MissingCapability,
    PolicyViolation,
    UsageError,
    VerificationFailed,
)
from aipm.domain.ids import is_valid_id
from aipm.domain.models import ProjectContext, Task, TasksDoc, TaskStatus, ToolName, Workspace
from aipm.domain.phase import InputState, prompt_inputs
from aipm.domain.scheduler import FINISHED, waves
from aipm.execution import git
from aipm.execution.process import is_inside
from aipm.execution.sandbox import resolve_sandbox
from aipm.execution.worktree import WorktreeManager, check_integration_branch
from aipm.security.budget import RunBudget
from aipm.state.done_record import claimed

MAX_PARALLEL = 8
MAX_ONLY = 200


@dataclass(frozen=True, slots=True)
class BuildOptions:
    """The command's flags. `kind` is `build` or `run`; `run` names one task."""

    kind: str = "build"
    task_id: str | None = None
    tool: str | None = None
    parallel: int | None = None
    max_retries: int | None = None
    budget: float | None = None
    timeout: str | None = None
    only: str | None = None
    dry_run: bool = False
    accept_stale: bool = False
    no_cache: bool = False


@dataclass(frozen=True, slots=True)
class DryRunTask:
    """One task as a build would dispatch it."""

    task: str
    batch: int
    prompt_bytes: int
    argv: tuple[str, ...]


@dataclass(slots=True)
class BuildResult:
    """A build's summary, or what a dry run would do."""

    kind: str
    summary: BuildSummary | None = None
    batches: list[list[str]] = field(default_factory=list[list[str]])
    planned: list[DryRunTask] = field(default_factory=list[DryRunTask])
    warnings: list[str] = field(default_factory=list[str])

    def to_data(self) -> dict[str, object]:
        """The `--json` payload (ARCHITECTURE §16.2)."""
        if self.summary is None:
            return {
                "dry_run": True,
                "batches": self.batches,
                "tasks": [
                    {"task": t.task, "batch": t.batch, "prompt_bytes": t.prompt_bytes,
                     "argv": list(t.argv)}
                    for t in self.planned
                ],
                "warnings": list(self.warnings),
            }  # fmt: skip
        return {**self.summary.to_data(), "dry_run": False, "warnings": list(self.warnings)}


def _only(options: BuildOptions) -> frozenset[str] | None:
    if options.kind == "run":
        if options.task_id is None or not is_valid_id("task", options.task_id):
            raise UsageError(f"{options.task_id!r} is not a task ID such as T-007")
        return frozenset({options.task_id})
    if options.only is None:
        return None
    ids = [part.strip() for part in options.only.split(",") if part.strip()]
    if not ids or len(ids) > MAX_ONLY or not all(is_valid_id("task", i) for i in ids):
        raise UsageError("--only takes task IDs separated by commas, such as T-001,T-004")
    return frozenset(ids)


def _flags(options: BuildOptions) -> dict[str, object]:
    """The command-line layer of the config (ARCHITECTURE §15), checked here first."""
    flags: dict[str, object] = {}
    if options.kind == "run":
        flags["dispatch.parallel"] = 1
    elif options.parallel is not None:
        if not 1 <= options.parallel <= MAX_PARALLEL:
            raise UsageError(f"--parallel must be between 1 and {MAX_PARALLEL}")
        flags["dispatch.parallel"] = options.parallel
    if options.max_retries is not None:
        if not 0 <= options.max_retries <= 10:
            raise UsageError("--max-retries must be between 0 and 10")
        flags["dispatch.max_retries"] = options.max_retries
    if options.timeout is not None:
        try:
            duration_seconds(options.timeout)
        except ValueError as exc:
            raise UsageError(f"--timeout: {exc}") from None
        flags["dispatch.task_timeout"] = options.timeout
    if options.budget is not None:
        if not (math.isfinite(options.budget) and options.budget > 0):
            raise UsageError("--budget must be a positive amount in USD")
        flags["budget.run_usd"] = options.budget
    return flags


def require_clean(root: Path) -> None:
    """Exit 2 when anything outside `.pm/` differs from HEAD or is untracked."""
    dirty = [
        e.path or "(a name aipm cannot read)"
        for e in git.status_porcelain_v2(root)
        if e.kind != "ignored" and not (e.path or "").startswith(".pm/")
    ]
    if dirty:
        shown = ", ".join(dirty[:5]) + (", …" if len(dirty) > 5 else "")
        raise UsageError(
            f"the working tree is not clean: {shown}",
            hint="Commit or stash your changes first: agents build on committed work only.",
        )


def _check_run_task(tasks: TasksDoc, task_id: str) -> None:
    by_id = {t.id: t for t in tasks.tasks}
    task = by_id.get(task_id)
    if task is None:
        raise UsageError(f"there is no task {task_id} in .pm/tasks.yaml")
    if task.status not in (TaskStatus.TODO, TaskStatus.IN_PROGRESS):
        hints = {
            TaskStatus.DONE: f"It is done; `aipm task reset {task_id}` starts it again.",
            TaskStatus.SKIPPED: f"`aipm task reset {task_id}` starts it again.",
            TaskStatus.BLOCKED: f"Review it, then `aipm task unblock {task_id}`.",
        }
        raise UsageError(f"{task_id} is {task.status.value}", hint=hints.get(task.status))
    waiting = [
        d for d in task.depends_on if by_id.get(d) is None or by_id[d].status not in FINISHED
    ]
    if waiting:
        raise UsageError(
            f"{task_id} depends on {', '.join(waiting)}, which is not done",
            hint="Build its dependencies first, with `aipm build`.",
        )


def _detect(adapter: ToolAdapter, root: Path, cfg: Config, *, dry_run: bool) -> None:
    caps = adapter.detect(flags=True, repo=root)
    if not caps.found:
        raise MissingCapability(
            f"{adapter.name.value} is not installed, or only inside the repository",
            hint="Install it, or run tasks yourself with `aipm prompt` and `aipm verify`.",
        )
    if not caps.dispatchable:
        missing = ", ".join(caps.missing) or "its version"
        raise MissingCapability(
            f"the installed {adapter.name.value} {caps.version or ''} lacks what dispatch needs: "
            f"{missing}",
            hint="Upgrade it, or run tasks yourself with `aipm prompt` and `aipm verify`.",
        )
    worktrees = WorktreeManager(root).root
    if any(is_inside(part, worktrees) for part in (*caps.launcher, caps.path or "")):
        raise PolicyViolation(f"the {adapter.name.value} found on PATH is inside a task worktree")
    tool = cfg.dispatch.tools.get(adapter.name)
    # Only Claude Code can drop its API key (`bare: false`); every other agent runs with an
    # empty config home of its own, so it has no saved login to fall back on (ADR-0026).
    needs_key = adapter.name is not ToolName.CLAUDE or tool is None or tool.bare
    if needs_key and not dry_run:
        for name in adapter.required_env:
            if not os.environ.get(name):
                raise MissingCapability(
                    f"{name} is not set; a dispatched {adapter.name.value} needs an API key",
                    hint="Give coding agents a dedicated API key with a spend limit.",
                )


def _context_text(adapter: ToolAdapter, ctx: ProjectContext) -> str:
    for generated in adapter.context_files(ctx):
        if generated.path == "AGENTS.md":
            return generated.block
    return ""


def _dry_run(
    settings: BuildSettings, tasks: TasksDoc, ctx: ProjectContext, adapter: ToolAdapter
) -> tuple[list[list[str]], list[DryRunTask]]:
    serialized = tuple(settings.cfg.plan.serialized_paths)
    batches = waves(
        tasks.tasks, parallel=settings.parallel, serialized=serialized, only=settings.only
    )
    by_id = {t.id: t for t in tasks.tasks}
    worktrees = WorktreeManager(settings.root)
    tool = settings.cfg.dispatch.tools.get(adapter.name)
    # The sandbox is resolved only for a real run: the preview assumes `srt` is used when it
    # is on PATH.
    native = native_allowed(settings.cfg) and shutil.which("srt") is None
    planned: list[DryRunTask] = []
    attempt = Path("<attempt>")
    for number, batch in enumerate(batches, start=1):
        for task_id in batch:
            task: Task = by_id[task_id]
            spec = compile_task_spec(task, ctx, approval=settings.approval)
            prompt = render_within_budget(adapter, spec, ctx)
            limits = tool_limits(
                tool, timeout_s=settings.timeout_s, task_usd=settings.budget.task_usd,
                allowed_commands=tuple(g.allow_prefix for g in spec.verify if g.allow_prefix),
                native_sandbox=native,
            )  # fmt: skip
            ws = Workspace(
                root=worktrees.path(task_id), temp_dir=attempt / "agent",
                context_dir=attempt / "context",
                config_home=Path(f"<run>/{adapter.name.value}"),
            )  # fmt: skip
            argv = adapter.preview_argv(limits, ws)
            planned.append(DryRunTask(task_id, number, prompt.size, argv))
    return batches, planned


def _settings(
    root: Path, cfg: Config, options: BuildOptions, only: frozenset[str] | None, approval: str
) -> BuildSettings:
    budget = RunBudget.of(
        run_usd=cfg.budget.run_usd, task_usd=cfg.budget.task_usd, run_tokens=cfg.budget.run_tokens
    )
    return BuildSettings(
        root=root, cfg=cfg, kind=options.kind, parallel=cfg.dispatch.parallel,
        max_retries=cfg.dispatch.max_retries,
        timeout_s=float(duration_seconds(cfg.dispatch.task_timeout)), budget=budget, only=only,
        approval=approval, integration=check_integration_branch(cfg.git.integration_branch),
        no_cache=options.no_cache,
    )  # fmt: skip


def _raise_for(result: BuildResult) -> None:
    summary = result.summary
    if summary is None:
        return
    data = result.to_data()
    resume = "Run `aipm build` again to resume; finished tasks are kept."
    if summary.interrupted:
        raise Interrupted("the build was interrupted", hint=resume, data=data)
    if summary.severe:
        raise PolicyViolation(
            "a task was blocked by a security policy violation",
            hint="Review `aipm status` and the task's worktree before you unblock or reset it.",
            data=data,
        )
    if summary.budget_exceeded:
        raise BudgetExceeded(
            f"the run budget of ${summary.run_usd:.2f} is spent",
            hint="Raise budget.run_usd or pass --budget, then run `aipm build` again.",
            data=data,
        )
    if summary.blocked:
        raise VerificationFailed(
            f"{len(summary.blocked)} task(s) blocked",
            hint="See `aipm status`; fix the cause, then `aipm task unblock <T-ID>`.",
            data=data,
        )


def run(
    project: Path | None, options: BuildOptions, *, progress: ProgressSink | None = None
) -> BuildResult:
    """Run the use case."""
    root = find_repo_root(project)
    require_initialized(root)
    only = _only(options)
    flags = _flags(options)
    loaded = load_config(root, flags=flags)
    cfg = loaded.config
    adapter = get_adapter(parse_tool(options.tool, cfg.dispatch.default_tool))
    # Trust is checked without the command-line layer: --parallel, --max-retries, --timeout and
    # --budget are the person's own choice for this run and change nothing aipm executes, but
    # relaxing a tighten-only key is part of the surface (SECURITY.md §6).
    require_trusted(root, load_config(root) if flags else loaded, command=options.kind)
    if not cfg.dispatch.enabled:
        raise UsageError(
            "dispatch is turned off (dispatch.enabled: false)",
            hint="Run tasks yourself with `aipm prompt` and `aipm verify`.",
        )
    store = runtime.open_repo_store(root)
    warnings = list(loaded.warnings)
    with store.lock():
        snapshot, _ = read_snapshot(
            store, coverage_threshold=cfg.discover.coverage_threshold, trusted=True
        )
        checks = prompt_inputs(snapshot)
        warnings += require_inputs(store, options.kind, checks, accept_stale=options.accept_stale)
        approval = next((c.state.value for c in checks if c.state is not InputState.OK), "approved")
        tasks = snapshot.tasks
        if tasks is None:
            raise UsageError("there is no plan to build", hint="Run `aipm plan` first.")
        if options.kind == "run" and options.task_id is not None:
            _check_run_task(tasks, options.task_id)
        claimed_ids = claimed(root, tasks.tasks)
        if claimed_ids:
            # They still unlock the tasks after them (red-team v0.3, the owner's choice).
            warnings.append(
                f"done by the repository's claim only, with no gate passed on this machine: "
                f"{', '.join(claimed_ids)}; review them, or `aipm task reset` them"
            )
        require_clean(root)
        git.check_repo_config(root)
        settings = _settings(root, cfg, options, only, approval)
        _detect(adapter, root, cfg, dry_run=options.dry_run)
        ctx = build_context(snapshot, cfg)
        if options.dry_run:
            batches, planned = _dry_run(settings, tasks, ctx, adapter)
            return BuildResult(options.kind, batches=batches, planned=planned, warnings=warnings)
        temp = attempt_dir(root, "aipm-sandbox-")
        try:
            sandbox = resolve_sandbox(
                mode=cfg.dispatch.sandbox.value, require=cfg.security.require_sandbox,
                repo=root, temp_dir=temp, what="agents and gates",
            )  # fmt: skip
        finally:
            shutil.rmtree(temp, ignore_errors=True)
        loop = BuildLoop(
            settings, store=store, tasks=tasks, ctx=ctx, context_text=_context_text(adapter, ctx),
            adapter=adapter, runtime=sandbox.launcher, progress=progress,
            sandbox_warning=sandbox.warning,
        )  # fmt: skip
        summary = loop.run()
    result = BuildResult(options.kind, summary=summary, warnings=warnings + summary.warnings)
    _raise_for(result)
    if not summary.outcomes:
        _nothing_ran(tasks, only, options)
    return result


def _nothing_ran(tasks: TasksDoc, only: frozenset[str] | None, options: BuildOptions) -> None:
    """Exit 2 when tasks remain but none could start; `build` with every task done is fine."""
    wanted = [t for t in tasks.tasks if only is None or t.id in only]
    left = [t for t in wanted if t.status not in FINISHED]
    if not left:
        return
    blocked = sum(1 for t in left if t.status is TaskStatus.BLOCKED)
    started = [t.id for t in left if t.status is TaskStatus.IN_PROGRESS]
    hint = "Unblock or reset blocked tasks with `aipm task`."
    if started:
        hint = (
            f"{started[0]} is in progress in manual mode: `aipm verify {started[0]}`, or "
            f"`aipm task reset {started[0]}` to let a build take it."
        )
    what = "the task" if options.kind == "run" else "no task"
    raise UsageError(f"{what} could not start: {len(left)} not done, {blocked} blocked", hint=hint)
