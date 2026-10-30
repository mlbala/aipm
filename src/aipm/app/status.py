"""`aipm status`: the worksheet view and security events, without an LLM (ARCHITECTURE §17).

Read-only: the state is read once without the lock (§6.4). Only `--ack` writes, under the lock:
it appends an `ack` event for an ID this machine recorded in `.pm/events.jsonl` that is not
itself an acknowledgement and is not acknowledged yet (§6.1).
"""

from dataclasses import dataclass
from pathlib import Path

from aipm.app import runtime
from aipm.app.snapshot import load_state
from aipm.app.workspace import find_repo_root, require_initialized
from aipm.config.loader import load_config
from aipm.domain.errors import UsageError
from aipm.domain.ids import is_valid_id
from aipm.domain.models import SecurityEventKind, Task
from aipm.domain.phase import derive_phase
from aipm.reporting.status import StatusView, build_status, render_status, render_task
from aipm.state.store import FileStateStore, open_store


@dataclass(frozen=True, slots=True)
class StatusResult:
    """What `aipm status` shows."""

    lines: tuple[str, ...]
    view: StatusView | None = None
    task: Task | None = None
    acked: str | None = None
    warnings: tuple[str, ...] = ()

    def to_data(self) -> dict[str, object]:
        """The `--json` payload."""
        if self.acked is not None:
            return {"acked": self.acked}
        data: dict[str, object] = self.view.to_data() if self.view is not None else {}
        if self.task is not None:
            data["task"] = self.task.model_dump(mode="json")
        return data


def _ack(store: FileStateStore, event_id: str) -> StatusResult:
    if not is_valid_id("event", event_id):
        raise UsageError(f"--ack takes an event ID such as EV-0123456789ab, not {event_id!r}")
    with store.lock():
        events = store.read_events()
        target = next((e for e in events if e.id == event_id), None)
        if target is None or target.kind is SecurityEventKind.ACK:
            raise UsageError(
                f"{event_id} is not a security event recorded on this machine",
                hint="Run `aipm status` to list the unacknowledged events.",
            )
        if any(e.kind is SecurityEventKind.ACK and e.ack_of == event_id for e in events):
            raise UsageError(f"{event_id} is already acknowledged")
        store.append_event(
            SecurityEventKind.ACK,
            source="aipm status --ack",
            detail=f"acknowledged {event_id} ({target.kind.value})",
            ack_of=event_id,
        )
    return StatusResult(lines=(f"Acknowledged {event_id}.",), acked=event_id)


def run(
    project: Path | None, *, show_all: bool, task_id: str | None, ack: str | None
) -> StatusResult:
    """Run the use case."""
    root = find_repo_root(project)
    require_initialized(root)
    store = open_store(root, redactor=runtime.user_redactor(root))
    if ack is not None:
        return _ack(store, ack)
    if task_id is not None and not is_valid_id("task", task_id):
        raise UsageError(f"--task takes a task ID such as T-007, not {task_id!r}")
    loaded = load_config(root)
    state = load_state(store, loaded=loaded)
    phase = derive_phase(state.snapshot)
    view = build_status(state.snapshot, phase, store.read_events(), loaded.config.budget)
    if task_id is not None:
        task = next((t for t in view.tasks if t.id == task_id), None)
        if task is None:
            raise UsageError(f"there is no task {task_id} in .pm/tasks.yaml")
        return StatusResult(tuple(render_task(task)), view, task, warnings=state.warnings)
    return StatusResult(
        tuple(render_status(view, show_all=show_all)), view, warnings=state.warnings
    )
