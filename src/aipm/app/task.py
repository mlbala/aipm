"""`aipm task <show|reset|block|unblock|skip> <T-ID>`: manual task state control.

Every change is made under the `.pm/` lock and recorded in `approvals.yaml` (`task_changes`:
who, when, from what to what, and why). Unblocking a task blocked by a policy violation, and
skipping one (which lets the tasks that depend on it start), are security events too. A change
touches only progress fields (status, attempts, base commit), so the G3 approval of the plan
stays valid (ADR-0016).

- `reset`: back to `todo`; attempts, base commit and attempt snapshot are cleared.
- `block --reason`: `todo` or `in_progress` to `blocked` (`manual`).
- `unblock`: `blocked` to `in_progress` when the task has a base commit, else `todo`.
- `skip`: `todo`, `in_progress` or `blocked` to `skipped`.
"""

from dataclasses import dataclass
from datetime import UTC, datetime
from enum import StrEnum
from pathlib import Path

from aipm.app import runtime
from aipm.app.approve import approver, load_approvals
from aipm.app.workspace import find_repo_root, require_initialized
from aipm.domain.errors import UsageError
from aipm.domain.ids import is_valid_id
from aipm.domain.models import (
    ArtifactKind,
    Blocked,
    BlockedReason,
    SecurityEventKind,
    Task,
    TaskChange,
    TaskChangeAction,
    TasksDoc,
    TaskStatus,
)
from aipm.reporting.worksheet import WORKSHEET_FILE, render_worksheet
from aipm.security.sanitize import sanitize_text
from aipm.state.attempts import delete_snapshot, load_snapshot
from aipm.state.store import FileStateStore


class Action(StrEnum):
    """What `aipm task` does."""

    SHOW = "show"
    RESET = "reset"
    BLOCK = "block"
    UNBLOCK = "unblock"
    SKIP = "skip"


_FROM: dict[Action, frozenset[TaskStatus]] = {
    Action.RESET: frozenset(
        {TaskStatus.IN_PROGRESS, TaskStatus.BLOCKED, TaskStatus.DONE, TaskStatus.SKIPPED}
    ),
    Action.BLOCK: frozenset({TaskStatus.TODO, TaskStatus.IN_PROGRESS}),
    Action.UNBLOCK: frozenset({TaskStatus.BLOCKED}),
    Action.SKIP: frozenset({TaskStatus.TODO, TaskStatus.IN_PROGRESS, TaskStatus.BLOCKED}),
}


@dataclass(frozen=True, slots=True)
class TaskResult:
    """The task after the action, and what changed."""

    task: Task
    action: Action
    previous: TaskStatus
    snapshot: bool

    def to_data(self) -> dict[str, object]:
        """The `--json` payload."""
        return {
            "action": self.action.value,
            "previous": self.previous.value,
            "attempt_snapshot": self.snapshot,
            "task": self.task.model_dump(mode="json"),
        }


def _reason(reason: str | None) -> str:
    return " ".join(sanitize_text(reason or "", source="--reason").text.split())[:300]


def _load(store: FileStateStore, task_id: str) -> tuple[TasksDoc, Task]:
    if not store.exists(ArtifactKind.TASKS):
        raise UsageError("there is no plan yet", hint="Run `aipm plan` first.")
    doc = store.load(ArtifactKind.TASKS)
    if not isinstance(doc, TasksDoc):  # pragma: no cover - the store's mapping
        raise UsageError("tasks.yaml did not load as a plan")
    task = next((t for t in doc.tasks if t.id == task_id), None)
    if task is None:
        raise UsageError(f"there is no task {task_id} in .pm/tasks.yaml")
    return doc, task


def _changed(task: Task, action: Action, reason: str) -> Task:
    if action is Action.RESET:
        update: dict[str, object] = {"status": TaskStatus.TODO, "attempts": 0, "base_sha": None,
                                     "blocked": None, "done": None}  # fmt: skip
    elif action is Action.BLOCK:
        update = {"status": TaskStatus.BLOCKED,
                  "blocked": Blocked(reason=BlockedReason.MANUAL, detail=reason)}  # fmt: skip
    elif action is Action.UNBLOCK:
        status = TaskStatus.IN_PROGRESS if task.base_sha is not None else TaskStatus.TODO
        update = {"status": status, "blocked": None}
    else:
        update = {"status": TaskStatus.SKIPPED, "blocked": None}
    return task.model_copy(update=update)


def _record(store: FileStateStore, before: Task, after: Task, action: Action, reason: str) -> None:
    entry = TaskChange(task=before.id, action=TaskChangeAction(action.value),
                       from_status=before.status, to_status=after.status, reason=reason,
                       by=approver(), at=datetime.now(UTC))  # fmt: skip
    doc = load_approvals(store)
    store.save(doc.model_copy(update={"task_changes": [*doc.task_changes, entry]}))
    policy_block = (
        before.blocked is not None and before.blocked.reason is BlockedReason.POLICY_VIOLATION
    )
    if action is Action.SKIP or (action is Action.UNBLOCK and policy_block):
        what = "skipped" if action is Action.SKIP else "unblocked after a policy violation"
        store.append_event(
            SecurityEventKind.TASK_CHANGE,
            source=f"task:{before.id}",
            detail=f"{before.id} was {what} by hand: {reason or '(no reason given)'}",
            data={"action": action.value, "from": before.status.value},
        )


def run(project: Path | None, *, action: str, task_id: str, reason: str | None) -> TaskResult:
    """Run the use case."""
    root = find_repo_root(project)
    require_initialized(root)
    act = Action(action)
    if not is_valid_id("task", task_id):
        raise UsageError(f"{task_id!r} is not a task ID such as T-007")
    clean = _reason(reason)
    if act is Action.BLOCK and not clean:
        raise UsageError("`aipm task block` needs --reason")
    if act is Action.SHOW and reason is not None:
        raise UsageError("`aipm task show` takes no --reason")
    store = runtime.open_repo_store(root)
    if act is Action.SHOW:
        _, task = _load(store, task_id)
        return TaskResult(task, act, task.status, load_snapshot(root, task.id) is not None)
    with store.lock():
        doc, task = _load(store, task_id)
        if task.status not in _FROM[act]:
            raise UsageError(f"cannot {act.value} {task.id}: it is {task.status.value}")
        after = _changed(task, act, clean)
        updated = doc.model_copy(
            update={"tasks": [after if t.id == task.id else t for t in doc.tasks]}
        )
        store.save(updated)
        store.write_text(WORKSHEET_FILE, render_worksheet(updated))
        _record(store, task, after, act, clean)
        if act in (Action.RESET, Action.SKIP):
            delete_snapshot(root, task.id)
    return TaskResult(after, act, task.status, load_snapshot(root, task.id) is not None)
