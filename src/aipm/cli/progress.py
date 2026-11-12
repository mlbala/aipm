"""Live build progress and the end-of-run summary for `aipm build` and `aipm run`.

Each task gets one line: its state, attempt and the run's spend. With a terminal on stderr the
lines are a Rich `Live` table; otherwise each change is printed as a plain line on stderr. Every
cell is sanitized text (task details can hold an agent's question), never markup.
"""

import shlex
import sys
from types import TracebackType
from typing import TYPE_CHECKING, cast

from aipm.security.sanitize import sanitize_text

if TYPE_CHECKING:
    from rich.console import Console
    from rich.live import Live
    from rich.table import Table

    from aipm.app.build_loop import Progress


def _clean(text: object, limit: int = 200) -> str:
    return " ".join(sanitize_text(str(text), source="build output").text.split())[:limit]


def _console() -> "Console":
    from rich.console import Console

    return Console(
        stderr=True, highlight=False, emoji=False, markup=False, soft_wrap=True, no_color=True
    )


class ProgressView:
    """Receives `Progress` events on the build's event loop; `live` draws a table."""

    def __init__(self, *, live: bool) -> None:
        self.live = live
        self.rows: dict[str, tuple[str, str, str]] = {}
        self.spent = 0.0
        self._console = _console()
        self._live: Live | None = None

    def __enter__(self) -> "ProgressView":
        if self.live:
            from rich.live import Live

            self._live = Live(self._table(), console=self._console, refresh_per_second=4)
            self._live.start()
        return self

    def __exit__(
        self,
        kind: type[BaseException] | None,
        exc: BaseException | None,
        tb: TracebackType | None,
    ) -> None:
        if self._live is not None:
            self._live.update(self._table())
            self._live.stop()
            self._live = None

    def __call__(self, event: "Progress") -> None:
        self.spent = event.spent_usd
        attempt = "" if event.attempt is None else f"attempt {event.attempt}"
        detail = _clean(event.detail or "")
        if event.state == "warning" or event.task == "*":
            self._print(f"{'warning' if event.state == 'warning' else 'note'}: {detail}")
            return
        self.rows[event.task] = (event.state, attempt, detail)
        if self._live is not None:
            self._live.update(self._table())
        else:
            parts = [event.task, event.state, attempt, f"${self.spent:.2f}", detail]
            self._print("  ".join(p for p in parts if p))

    def _print(self, line: str) -> None:
        from rich.text import Text

        target = self._live.console if self._live is not None else self._console
        target.print(Text(_clean(line, 400)))

    def _table(self) -> "Table":
        from rich.table import Table
        from rich.text import Text

        table = Table(show_header=True, header_style=None, box=None, pad_edge=False)
        for title in ("task", "state", "attempt", "detail"):
            table.add_column(Text(title))
        for task, (state, attempt, detail) in sorted(self.rows.items()):
            table.add_row(Text(task), Text(state), Text(attempt), Text(detail))
        table.caption = Text(f"spent ${self.spent:.2f}")
        return table


def progress_view(*, json: bool) -> ProgressView:
    """A live table on a terminal; plain lines otherwise (and never on stdout)."""
    return ProgressView(live=not json and sys.stderr.isatty())


def _records(value: object) -> list[dict[str, object]]:
    items = cast("list[object]", value) if isinstance(value, list) else []
    return [cast("dict[str, object]", item) for item in items if isinstance(item, dict)]


def show(data: dict[str, object]) -> list[str]:
    """The lines of a build result (from its JSON data) for a human, already sanitized."""
    lines: list[str] = []
    if data.get("dry_run"):
        batches = cast("list[list[str]]", data.get("batches") or [])
        lines.append(f"Dry run: {len(batches)} batch(es); nothing is dispatched.")
        for number, batch in enumerate(batches, start=1):
            lines.append(f"  batch {number}: {', '.join(_clean(b, 20) for b in batch)}")
        for task in _records(data.get("tasks")):
            argv = cast("list[str]", task.get("argv") or [])
            lines.append(f"{task.get('task')} (prompt {task.get('prompt_bytes')} bytes):")
            lines.append(f"  {_clean(shlex.join(argv), 4000)}")
        return lines
    lines.append(
        f"Run {data.get('run_id')}{' (resumed)' if data.get('resumed') else ''}: "
        f"spent ${float(cast('float', data.get('spent_usd') or 0.0)):.2f} of "
        f"${float(cast('float', data.get('run_usd') or 0.0)):.2f}; integration branch "
        f"{_clean(data.get('integration'), 100)}"
    )
    for task in _records(data.get("tasks")):
        status = _clean(task.get("status"), 20)
        line = f"  {task.get('task')}: {status} after {task.get('attempts')} attempt(s)"
        if task.get("commit"):
            line += f", commit {str(task.get('commit'))[:12]}"
        if task.get("reason"):
            line += f" ({_clean(task.get('reason'), 40)}: {_clean(task.get('detail') or '', 300)})"
        lines.append(line)
        if task.get("question"):
            lines.append(f"    agent says: {_clean(task.get('question'), 300)}")
    if data.get("budget_exceeded"):
        lines.append("The run budget is spent: no task was dispatched after that.")
    if data.get("interrupted"):
        lines.append("Interrupted: run `aipm build` again to resume.")
    if not _records(data.get("tasks")):
        lines.append("Nothing to build.")
    else:
        lines.append("Review the work with `aipm merge`, which shows the log before it merges.")
    return lines
