"""The append-only run journal for resume and audit (C-19, ARCHITECTURE §6.3, §12.6).

`Journal.append` writes one `JournalEvent` per line to `.pm/runs/<run-id>/journal.jsonl`
through the state store, which cleans and redacts the line, fsyncs it, and records the file's
new hash in the write ledger outside the repository.

`.pm/runs/` is ignored by git, so a journal planted there (or shipped with a copied repository)
could claim that a task's commit is ready to merge. `load` reads a journal only if the ledger
says aipm wrote it; `find_resumable` and `replay` work only on what `load` returns, and the
build loop still checks every claim against git (the commit's trailers) before acting on it.
"""

from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from datetime import UTC, datetime

from pydantic import JsonValue, ValidationError

from aipm.domain.ids import is_valid_id
from aipm.domain.models import JournalEvent, JournalEventType
from aipm.state.store import FileStateStore

JOURNAL_FILE = "journal.jsonl"
BUILD_KINDS = frozenset({"build", "run"})
"""`run_started.data.kind` of the runs `aipm build` may resume."""


class Journal:
    """The journal of one run. `seq` continues where a resumed journal stopped."""

    def __init__(self, store: FileStateStore, run_id: str, *, seq: int = 0) -> None:
        self.store = store
        self.run_id = run_id
        self.seq = seq

    def append(
        self,
        kind: JournalEventType,
        *,
        task: str | None = None,
        attempt: int | None = None,
        data: Mapping[str, JsonValue] | None = None,
    ) -> JournalEvent:
        """Append one event and fsync it."""
        event = JournalEvent(
            seq=self.seq,
            ts=datetime.now(UTC),
            run=self.run_id,
            type=kind,
            task=task,
            attempt=attempt,
            data=dict(data or {}),
        )
        self.store.append_run_line(self.run_id, [JOURNAL_FILE], event.model_dump_json())
        self.seq += 1
        return event


def load(store: FileStateStore, run_id: str) -> list[JournalEvent] | None:
    """The events of `run_id`, or `None` when aipm did not write that journal (the ledger).

    Lines that do not parse, or that name another run, are skipped.
    """
    lines = store.run_lines(run_id, [JOURNAL_FILE])
    if lines is None:
        return None
    events: list[JournalEvent] = []
    for line in lines:
        try:
            event = JournalEvent.model_validate_json(line)
        except ValidationError:
            continue
        if event.run == run_id:
            events.append(event)
    return events


def _started(events: Sequence[JournalEvent]) -> JournalEvent | None:
    for event in events:
        if event.type is JournalEventType.RUN_STARTED and event.data.get("kind") in BUILD_KINDS:
            return event
    return None


def find_resumable(store: FileStateStore) -> str | None:
    """The newest build run, if its journal has no `run_finished` (ARCHITECTURE §12.6).

    Runs are ordered by their `run_started` time, since run IDs only name the minute. An older
    unfinished run behind a finished one is never resumed.
    """
    newest: tuple[datetime, str] | None = None
    finished: dict[str, bool] = {}
    for run_id in store.run_ids():
        events = load(store, run_id)
        started = _started(events or [])
        if started is None or events is None:
            continue
        finished[run_id] = any(e.type is JournalEventType.RUN_FINISHED for e in events)
        if newest is None or (started.ts, run_id) > newest:
            newest = (started.ts, run_id)
    if newest is None or finished[newest[1]]:
        return None
    return newest[1]


@dataclass(slots=True)
class TaskReplay:
    """What the journal says happened to one task in the run."""

    task: str
    attempts: int = 0
    dispatches: int = 0
    committed: str | None = None
    committed_attempt: int | None = None
    merged: str | None = None
    blocked: bool = False


@dataclass(slots=True)
class RunReplay:
    """A run's journal, summed up for resume."""

    run_id: str
    kind: str | None = None
    integration: str | None = None
    base: str | None = None
    spent_usd: float = 0.0
    task_usd: float = 0.0
    next_seq: int = 0
    tasks: dict[str, TaskReplay] = field(default_factory=dict[str, TaskReplay])

    def task(self, task_id: str) -> TaskReplay:
        """The replay of `task_id`, created empty on first use."""
        return self.tasks.setdefault(task_id, TaskReplay(task_id))


def _text(data: Mapping[str, JsonValue], key: str) -> str | None:
    value = data.get(key)
    return value if isinstance(value, str) else None


def _sha(data: Mapping[str, JsonValue], key: str) -> str | None:
    value = _text(data, key)
    if (
        value is None
        or len(value) not in (40, 64)
        or not all(c in "0123456789abcdef" for c in value)
    ):
        return None
    return value


def _cost(data: Mapping[str, JsonValue]) -> float:
    value = data.get("cost_usd")
    if isinstance(value, bool) or not isinstance(value, int | float):
        return 0.0
    return float(value) if 0 <= value < 1_000_000 else 0.0


def replay(run_id: str, events: Sequence[JournalEvent]) -> RunReplay:
    """Sum up the events of one run: spend (each attempt's own cost, and the task budget for an
    agent that started but never finished), and per task its attempts, its last commit, whether
    it was merged and whether it was blocked. Pure."""
    state = RunReplay(run_id)
    unfinished = 0
    for event in events:
        state.next_seq = max(state.next_seq, event.seq + 1)
        data = event.data
        if event.type is JournalEventType.RUN_STARTED:
            state.kind = _text(data, "kind")
            state.integration = _text(data, "integration")
            state.base = _sha(data, "base")
            state.task_usd = _cost({"cost_usd": data.get("task_usd")})
            continue
        if event.type is JournalEventType.AGENT_STARTED:
            unfinished += 1
        if event.type is JournalEventType.AGENT_FINISHED:
            unfinished = max(unfinished - 1, 0)
            state.spent_usd += _cost(data)
        if event.task is None or not is_valid_id("task", event.task):
            continue
        task = state.task(event.task)
        if event.attempt is not None:
            task.attempts = max(task.attempts, event.attempt)
        if event.type is JournalEventType.AGENT_STARTED:
            task.dispatches += 1
        elif event.type is JournalEventType.TASK_COMMITTED:
            task.committed = _sha(data, "commit")
            task.committed_attempt = event.attempt
            task.merged = None
        elif event.type is JournalEventType.TASK_MERGED:
            task.merged = _sha(data, "commit")
        elif event.type is JournalEventType.TASK_BLOCKED:
            task.blocked = True
    # An agent started but never reported (aipm was killed): charged its whole task budget.
    state.spent_usd += unfinished * state.task_usd
    return state
