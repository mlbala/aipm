"""`aipm auto` (v0.4): run the next step until built; never records trust (§7.3)."""

from typing import Annotated

import typer

from aipm.cli.commands._options import (
    AcceptRisk,
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
    yes: Annotated[
        bool, typer.Option("-y", "--yes", help="Skip the G1-G3 review gates only.")
    ] = False,
    accept_risk: AcceptRisk = False,
    accept_stale: AcceptStale = False,
    tool: Tool = None,
    parallel: Parallel = None,
    max_retries: MaxRetries = None,
    budget: Budget = None,
    timeout: Timeout = None,
    only: Only = None,
    dry_run: DryRun = False,
) -> None:
    """Run every step in order, pausing at the review gates."""
    not_available(ctx, "auto", "v0.4")
