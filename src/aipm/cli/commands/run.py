"""`aipm run <T-ID>` (v0.3): one attempt loop for one task (ARCHITECTURE §12.4)."""

import typer

from aipm.cli.commands._options import AcceptStale, Budget, DryRun, TaskId, Timeout, Tool
from aipm.cli.output import not_available


def command(
    ctx: typer.Context,
    task_id: TaskId,
    tool: Tool = None,
    timeout: Timeout = None,
    budget: Budget = None,
    dry_run: DryRun = False,
    accept_stale: AcceptStale = False,
) -> None:
    """Dispatch one task to a coding agent and verify the result."""
    not_available(ctx, "run", "v0.3")
