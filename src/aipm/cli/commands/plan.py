"""`aipm plan` (v0.1): the task graph (ARCHITECTURE §9)."""

from typing import Annotated

import typer

from aipm.cli.commands._options import AcceptRisk, AcceptStale
from aipm.cli.output import not_implemented_yet


def command(
    ctx: typer.Context,
    max_tasks: Annotated[
        int | None, typer.Option("--max-tasks", metavar="N", help="Maximum number of tasks.")
    ] = None,
    accept_risk: AcceptRisk = False,
    accept_stale: AcceptStale = False,
) -> None:
    """Split the work into a task graph with acceptance criteria and gates."""
    not_implemented_yet(ctx, "plan", prompt="04")
