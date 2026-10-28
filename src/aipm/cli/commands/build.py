"""`aipm build` (v0.3): every ready task, in parallel where safe (ARCHITECTURE §12)."""

import typer

from aipm.cli.commands._options import (
    AcceptStale,
    Budget,
    DryRun,
    MaxRetries,
    Only,
    Parallel,
    Timeout,
    Tool,
)
from aipm.cli.output import not_available


def command(
    ctx: typer.Context,
    tool: Tool = None,
    parallel: Parallel = None,
    max_retries: MaxRetries = None,
    budget: Budget = None,
    timeout: Timeout = None,
    only: Only = None,
    dry_run: DryRun = False,
    accept_stale: AcceptStale = False,
) -> None:
    """Build every ready task with coding agents, verifying each one."""
    not_available(ctx, "build", "v0.3")
