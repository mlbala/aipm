"""`aipm verify <T-ID>` (v0.2): post-change checks and gates for one task."""

from typing import Annotated

import typer

from aipm.cli.commands._options import AcceptRisk, AcceptStale, TaskId
from aipm.cli.output import not_available


def command(
    ctx: typer.Context,
    task_id: TaskId,
    commit: Annotated[
        bool, typer.Option("--commit", help="Commit the result with aipm trailers.")
    ] = False,
    base: Annotated[
        str | None, typer.Option("--base", metavar="SHA", help="Diff from this commit.")
    ] = None,
    gate: Annotated[
        str | None, typer.Option("--gate", metavar="NAME", help="Run one gate only.")
    ] = None,
    override_ac: Annotated[
        str | None,
        typer.Option(
            "--override-ac", metavar="ID", help="Override an acceptance-criterion veto (logged)."
        ),
    ] = None,
    reason: Annotated[
        str | None, typer.Option("--reason", help="Why the override is justified.")
    ] = None,
    accept_risk: AcceptRisk = False,
    accept_stale: AcceptStale = False,
) -> None:
    """Run the post-change checks and every gate for one task."""
    not_available(ctx, "verify", "v0.2")
