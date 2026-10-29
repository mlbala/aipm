"""The status view: counts, blocked tasks, security events, coverage, spend (ARCHITECTURE §17).

Pure: built from the snapshot, the phase report and the security events; no LLM, no network.
Task text and event details are untrusted, so the CLI prints the rendered lines with
`print_untrusted`.
"""

from collections import Counter
from collections.abc import Sequence
from dataclasses import dataclass

from aipm.config.schema import BudgetConfig
from aipm.domain.models import (
    Priority,
    SecurityEvent,
    SecurityEventKind,
    Severity,
    StateSnapshot,
    Task,
    TaskStatus,
)
from aipm.domain.phase import PhaseReport

BAR_WIDTH = 30
_AT_LEAST_MEDIUM = frozenset({Severity.MEDIUM, Severity.HIGH, Severity.CRITICAL})


def unacknowledged(events: Sequence[SecurityEvent]) -> list[SecurityEvent]:
    """Security events that no `ack` event acknowledges, oldest first."""
    acked = {e.ack_of for e in events if e.kind is SecurityEventKind.ACK}
    return [e for e in events if e.kind is not SecurityEventKind.ACK and e.id not in acked]


def progress_bar(finished: int, total: int, width: int = BAR_WIDTH) -> str:
    """`[#######-----------------------]  25% (2/8)`."""
    filled = 0 if total == 0 else round(width * finished / total)
    percent = 0 if total == 0 else round(100 * finished / total)
    return f"[{'#' * filled}{'-' * (width - filled)}] {percent:3d}% ({finished}/{total})"


@dataclass(frozen=True, slots=True)
class BlockedView:
    """A blocked task, why, and the question for the human."""

    id: str
    title: str
    reason: str
    detail: str
    question: str | None


@dataclass(frozen=True, slots=True)
class EventView:
    """One unacknowledged security event."""

    id: str
    ts: str
    kind: str
    source: str
    detail: str


@dataclass(frozen=True, slots=True)
class StatusView:
    """Everything `aipm status` shows."""

    phase: PhaseReport
    counts: tuple[tuple[str, int], ...]
    total: int
    finished: int
    blocked: tuple[BlockedView, ...]
    events: tuple[EventView, ...]
    uncovered_features: tuple[str, ...]
    uncovered_threats: tuple[str, ...]
    budget: BudgetConfig
    tasks: tuple[Task, ...]

    def to_data(self) -> dict[str, object]:
        """The `--json` payload."""
        return {
            "phase": self.phase.to_data(),
            "counts": dict(self.counts),
            "total": self.total,
            "finished": self.finished,
            "blocked": [
                {"id": b.id, "title": b.title, "reason": b.reason, "detail": b.detail,
                 "question": b.question}
                for b in self.blocked
            ],
            "security_events": [
                {"id": e.id, "ts": e.ts, "kind": e.kind, "source": e.source, "detail": e.detail}
                for e in self.events
            ],
            "uncovered": {"features": list(self.uncovered_features),
                          "threats": list(self.uncovered_threats)},
            "spend": {"usd": None, "tokens": None, "budget_run_usd": self.budget.run_usd,
                      "budget_task_usd": self.budget.task_usd,
                      "budget_run_tokens": self.budget.run_tokens},
            "tasks": [{"id": t.id, "status": t.status.value, "title": t.title}
                      for t in self.tasks],
        }  # fmt: skip


def build_status(
    snapshot: StateSnapshot,
    phase: PhaseReport,
    events: Sequence[SecurityEvent],
    budget: BudgetConfig,
) -> StatusView:
    """Count, collect and cross-reference; `events` is the local `events.jsonl`."""
    tasks = tuple(sorted(snapshot.tasks.tasks if snapshot.tasks else [], key=lambda t: t.id))
    counts = Counter(t.status for t in tasks)
    done_traces = {tr for t in tasks if t.status is TaskStatus.DONE for tr in t.traces}
    features = snapshot.prd.meta.features if snapshot.prd else []
    threats = snapshot.threat_model.meta.threats if snapshot.threat_model else []
    blocked = tuple(
        BlockedView(t.id, t.title, t.blocked.reason.value, t.blocked.detail, t.blocked.question)
        for t in tasks
        if t.blocked is not None
    )
    return StatusView(
        phase=phase,
        counts=tuple((s.value, counts[s]) for s in TaskStatus),
        total=len(tasks),
        finished=counts[TaskStatus.DONE] + counts[TaskStatus.SKIPPED],
        blocked=blocked,
        events=tuple(
            EventView(e.id, e.ts.strftime("%Y-%m-%dT%H:%M:%SZ"), e.kind.value, e.source, e.detail)
            for e in unacknowledged(events)
        ),
        uncovered_features=tuple(
            f"{f.id} ({f.priority.value}): {f.title}"
            for f in features
            if f.priority is not Priority.WONT and f.id not in done_traces
        ),
        uncovered_threats=tuple(
            f"{t.id} ({t.severity.value}): {t.title}"
            for t in threats
            if t.severity in _AT_LEAST_MEDIUM and t.id not in done_traces
        ),
        budget=budget,
        tasks=tasks,
    )


def _line(text: str) -> str:
    return " ".join(text.split())


def render_status(view: StatusView, *, show_all: bool = False) -> list[str]:
    """The lines `aipm status` prints."""
    lines = [f"Phase: {view.phase.phase.value}"]
    lines.extend(f"stale: {impact}" for impact in view.phase.impacts)
    lines.extend(f"blocked: {b}" for b in view.phase.blockers)
    lines.append(f"Next: {view.phase.next_command or 'nothing; the plan is built'}")
    lines.append("")
    counts = ", ".join(f"{name.replace('_', ' ')} {n}" for name, n in view.counts)
    lines.append(f"Tasks: {view.total} ({counts})")
    lines.append(progress_bar(view.finished, view.total))
    if view.blocked:
        lines.append("")
        lines.append("Blocked tasks:")
        for b in view.blocked:
            lines.append(f"  {b.id} {_line(b.title)}: {b.reason}")
            if b.detail:
                lines.append(f"    {_line(b.detail)}")
            if b.question:
                lines.append(f"    question: {_line(b.question)}")
    lines.append("")
    if view.events:
        lines.append(f"Security events ({len(view.events)} unacknowledged):")
        for e in view.events:
            lines.append(f"  {e.id} {e.ts} {e.kind} [{_line(e.source)}] {_line(e.detail)}")
        lines.append("  Acknowledge one with `aipm status --ack EVENT-ID`.")
    else:
        lines.append("Security events: none unacknowledged")
    lines.append("")
    lines.append("Not yet covered by done tasks:")
    lines.append(f"  features: {'; '.join(view.uncovered_features) or 'none'}")
    lines.append(f"  threats (medium or higher): {'; '.join(view.uncovered_threats) or 'none'}")
    b = view.budget
    lines.append("")
    lines.append(
        f"Spend: not recorded yet (arrives with builds in v0.3); budget ${b.run_usd:.2f} per run, "
        f"${b.task_usd:.2f} per task, {b.run_tokens} tokens per run"
    )
    if show_all and view.tasks:
        lines.append("")
        lines.append("All tasks:")
        for t in view.tasks:
            deps = f" (after {', '.join(t.depends_on)})" if t.depends_on else ""
            lines.append(f"  {t.id} [{t.status.value}] {t.size.value} {_line(t.title)}{deps}")
    return lines


def render_task(task: Task) -> list[str]:
    """`aipm status --task T-ID`: one task in full."""
    lines = [
        f"{task.id}: {_line(task.title)}",
        f"  status: {task.status.value}   type: {task.type.value}   size: {task.size.value}   "
        f"attempts: {task.attempts}",
        f"  traces: {', '.join(task.traces) or 'none'}",
        f"  depends on: {', '.join(task.depends_on) or 'none'}",
        f"  owns: {', '.join(task.owns_files) or 'none'}",
        f"  reads: {', '.join(task.reads_files) or 'none'}",
        f"  gates: {', '.join(task.gates) or 'none'}",
        "  new dependencies: "
        + (", ".join(f"{d.ecosystem.value}:{d.name}" for d in task.deps_add) or "none"),
    ]
    if task.blocked is not None:
        lines.append(f"  blocked: {task.blocked.reason.value} {_line(task.blocked.detail)}")
        if task.blocked.question:
            lines.append(f"  question: {_line(task.blocked.question)}")
    if task.done is not None:
        lines.append(f"  done: {task.done.commit[:12]} at {task.done.at.isoformat()}")
    if task.description.strip():
        lines.append("  description:")
        lines.extend(f"    {line}" for line in task.description.strip().splitlines())
    lines.append("  acceptance criteria:")
    lines.extend(f"    {c.id}: {_line(c.text)}" for c in task.acceptance)
    return lines
