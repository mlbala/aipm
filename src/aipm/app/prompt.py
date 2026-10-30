"""`aipm prompt <T-ID>`: the task prompt for your own coding agent (ARCHITECTURE §12.7).

The prompt's checks carry gate argv that the agent runs outside aipm's sandbox, so the command
needs trust first (exit 6, SECURITY.md §6 rule 3). It also needs the approved, current plan
(G3), unless `--accept-stale`, which is recorded. A task that is done, skipped or blocked is
refused, and so is one whose dependencies are not finished, unless `--force` (exit 2).

The prompt is compiled without an LLM (`aipm.adapters.compiler`), written to
`.pm/prompts/<T-ID>.<tool>.md` through the state store (redacted), and the task becomes
`in_progress` with `base_sha` set to HEAD (kept if the task was already in progress). What is
printed, written to `--out` or copied is exactly the text the store wrote. When the task starts,
its attempt snapshot is taken outside the repository, for `verify` (ADR-0021).

`--fix` adds the failing output of the last verify. `verify` arrives in v0.2, so for now the
saved gate report is named with `--report FILE`.
"""

import os
from collections.abc import Sequence
from dataclasses import dataclass, field
from pathlib import Path

from pydantic import ValidationError

from aipm.adapters.compiler import compile_task_spec, render_within_budget
from aipm.adapters.registry import get_adapter, parse_tool
from aipm.app import runtime
from aipm.app.approve import require_inputs
from aipm.app.attempt import take_snapshot
from aipm.app.inputs import read_repo_file
from aipm.app.project_context import build_context
from aipm.app.snapshot import read_snapshot
from aipm.app.trust import require_trusted
from aipm.app.workspace import find_repo_root, require_initialized
from aipm.config.loader import load_config
from aipm.domain.errors import InputRejected, SchemaError, UsageError
from aipm.domain.ids import is_valid_id
from aipm.domain.models import ArtifactKind, GateReport, Task, TasksDoc, TaskStatus
from aipm.domain.phase import InputState, prompt_inputs
from aipm.execution.clipboard import copy_text
from aipm.execution.git import head_sha
from aipm.reporting.worksheet import WORKSHEET_FILE, render_worksheet
from aipm.security.paths import safe_relpath
from aipm.state.attempts import load_snapshot
from aipm.state.repo_files import read_repo_bytes, write_repo_bytes
from aipm.state.store import FileStateStore
from aipm.state.yamlio import load_yaml

_FINISHED = frozenset({TaskStatus.DONE, TaskStatus.SKIPPED})


@dataclass(frozen=True, slots=True)
class PromptOptions:
    """The command's arguments and flags."""

    task_id: str
    tool: str | None = None
    copy: bool = False
    out: Path | None = None
    fix: bool = False
    report: Path | None = None
    force: bool = False
    accept_stale: bool = False


@dataclass(frozen=True, slots=True)
class PromptResult:
    """What `aipm prompt` did, for the CLI to report."""

    repo_root: str
    task_id: str
    tool: str
    text: str
    file: str
    base_sha: str
    fix: bool
    out: str | None = None
    copy_requested: bool = False
    copied_with: str | None = None
    omitted: tuple[str, ...] = ()
    warnings: tuple[str, ...] = field(default_factory=tuple[str, ...])

    def to_data(self) -> dict[str, object]:
        """The `--json` payload."""
        return {
            "repo": self.repo_root,
            "task": self.task_id,
            "tool": self.tool,
            "status": TaskStatus.IN_PROGRESS.value,
            "base_sha": self.base_sha,
            "fix": self.fix,
            "file": self.file,
            "out": self.out,
            "copied": self.copied_with,
            "bytes": len(self.text.encode("utf-8")),
            "omitted": list(self.omitted),
            "warnings": list(self.warnings),
            "prompt": self.text,
        }


def _check_options(options: PromptOptions) -> None:
    if not is_valid_id("task", options.task_id):
        raise UsageError(f"{options.task_id!r} is not a task ID such as T-007")
    if options.report is not None and not options.fix:
        raise UsageError("--report goes with --fix")
    if options.fix and options.report is None:
        raise UsageError(
            "--fix needs the failing checks: `aipm verify` saves them from v0.2 on",
            hint="For now, pass a saved gate report with --report FILE.",
        )


def _check_task(task: Task, tasks: TasksDoc, options: PromptOptions) -> list[str]:
    if task.status in _FINISHED:
        raise UsageError(
            f"{task.id} is {task.status.value}; there is nothing to prompt for",
            hint="Reopen it with `aipm task reset` (v0.2).",
        )
    if task.status is TaskStatus.BLOCKED:
        reason = task.blocked.reason.value if task.blocked is not None else "blocked"
        raise UsageError(
            f"{task.id} is blocked ({reason})", hint="Unblock it with `aipm task unblock` (v0.2)."
        )
    if options.fix and task.status is not TaskStatus.IN_PROGRESS:
        raise UsageError(
            f"--fix is for a task in progress, and {task.id} is {task.status.value}",
            hint=f"Run `aipm prompt {task.id}` first.",
        )
    status = {t.id: t.status for t in tasks.tasks}
    unfinished = [d for d in task.depends_on if status.get(d) not in _FINISHED]
    if not unfinished:
        return []
    if not options.force:
        raise UsageError(
            f"{task.id} depends on tasks that are not done: {', '.join(unfinished)}",
            hint="Finish them first, or pass --force to start anyway.",
        )
    return [f"--force: {task.id} started before {', '.join(unfinished)} finished"]


def load_report(root: Path, given: Path, task_id: str, *, max_bytes: int) -> GateReport:
    """Read a saved gate report (YAML or JSON) from inside the repository; all of it is T2."""
    file = read_repo_file(root, given, max_bytes=max_bytes, what="--report")
    try:
        text = file.data.decode("utf-8")
    except UnicodeDecodeError:
        raise InputRejected(f"--report {file.relpath} is not valid UTF-8") from None
    raw = load_yaml(text, source=file.relpath)
    try:
        report = GateReport.model_validate(raw if raw is not None else {})
    except ValidationError as exc:
        first = exc.errors()[0]
        where = ".".join(str(p) for p in first["loc"]) or "(file)"
        raise SchemaError(f"{file.relpath} is not a gate report: {where}: {first['msg']}") from None
    if report.task != task_id:
        raise UsageError(f"{file.relpath} is the report of {report.task}, not {task_id}")
    if not report.failures():
        raise UsageError(f"{file.relpath} shows no failing check; there is nothing to fix")
    return report


def write_out(root: Path, given: Path, text: str, *, extra_protected: Sequence[str] = ()) -> str:
    """Write the prompt to a user-named file inside the repository; returns its relative path.

    Only the directories on the way are resolved; the file itself is never followed if it is a
    link (`safe_relpath` and `write_repo_bytes` refuse, exit 6), and protected paths, including
    `security.extra_protected_paths`, are refused.
    """
    absolute = Path(os.path.normpath(given if given.is_absolute() else Path.cwd() / given))
    target = Path(os.path.realpath(absolute.parent)) / absolute.name
    try:
        rel = target.relative_to(root)
    except ValueError:
        raise UsageError(
            f"--out {given} is outside the repository",
            hint="To save the prompt elsewhere, redirect it: `aipm prompt T-ID > FILE`.",
        ) from None
    relpath = safe_relpath(root, rel.as_posix(), extra_protected=extra_protected)
    write_repo_bytes(root, relpath, text.encode("utf-8"), expected=read_repo_bytes(root, relpath))
    return relpath


def _record_start(store: FileStateStore, tasks: TasksDoc, task: Task, base_sha: str) -> None:
    started = task.model_copy(update={"status": TaskStatus.IN_PROGRESS, "base_sha": base_sha})
    doc = tasks.model_copy(
        update={"tasks": [started if t.id == task.id else t for t in tasks.tasks]}
    )
    store.save(doc)
    saved = store.load(ArtifactKind.TASKS)
    if isinstance(saved, TasksDoc):
        store.write_text(WORKSHEET_FILE, render_worksheet(saved))


def run(project: Path | None, options: PromptOptions) -> PromptResult:
    """Run the use case."""
    root = find_repo_root(project)
    require_initialized(root)
    _check_options(options)
    loaded = load_config(root)
    cfg = loaded.config
    tool = parse_tool(options.tool, cfg.dispatch.default_tool)
    adapter = get_adapter(tool)
    require_trusted(root, loaded, command="prompt")
    store = runtime.open_repo_store(root)
    with store.lock():
        snapshot, _ = read_snapshot(
            store, coverage_threshold=cfg.discover.coverage_threshold, trusted=True
        )
        warnings = list(loaded.warnings)
        checks = prompt_inputs(snapshot)
        warnings += require_inputs(store, "prompt", checks, accept_stale=options.accept_stale)
        approval = next((c.state.value for c in checks if c.state is not InputState.OK), "approved")
        tasks = snapshot.tasks
        task = next((t for t in tasks.tasks if t.id == options.task_id), None) if tasks else None
        if tasks is None or task is None:
            raise UsageError(f"there is no task {options.task_id} in .pm/tasks.yaml")
        warnings += _check_task(task, tasks, options)
        report = (
            load_report(root, options.report, task.id, max_bytes=cfg.security.max_input_kib * 1024)
            if options.report is not None
            else None
        )
        keep = task.status is TaskStatus.IN_PROGRESS and task.base_sha is not None
        base_sha = task.base_sha if keep and task.base_sha is not None else head_sha(root)
        ctx = build_context(snapshot, cfg)
        spec = compile_task_spec(task, ctx, previous=report, approval=approval)
        rendered = render_within_budget(adapter, spec, ctx)
        text, _ = store.save_prompt(
            task.id, tool.value, rendered.text, allowed_url_domains=ctx.allowed_url_domains
        )
        _record_start(store, tasks, task, base_sha)
        if not keep:
            take_snapshot(root, task.id, base_sha, cfg)
        elif load_snapshot(root, task.id) is None:
            warnings.append(
                f"{task.id} started before aipm kept attempt snapshots, so `aipm verify` will "
                f"refuse it: run `aipm task reset {task.id}`, then `aipm prompt {task.id}`"
            )
    out = (
        write_out(root, options.out, text, extra_protected=cfg.security.extra_protected_paths)
        if options.out is not None
        else None
    )
    copied = copy_text(text, cwd=root) if options.copy else None
    return PromptResult(
        repo_root=str(root),
        task_id=task.id,
        tool=tool.value,
        text=text,
        file=f".pm/prompts/{task.id}.{tool.value}.md",
        base_sha=base_sha,
        fix=options.fix,
        out=out,
        copy_requested=options.copy,
        copied_with=copied,
        omitted=rendered.omitted,
        warnings=tuple(warnings),
    )
