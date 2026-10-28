"""`aipm scan` (v0.2): every scanner over the whole repository."""

from typing import Annotated

import typer

from aipm.cli.output import not_available


def command(
    ctx: typer.Context,
    scanner: Annotated[
        str | None, typer.Option("--scanner", metavar="NAME", help="Run one scanner only.")
    ] = None,
    fail_on: Annotated[
        str | None,
        typer.Option("--fail-on", metavar="SEVERITY", help="Lowest severity that fails."),
    ] = None,
) -> None:
    """Run every scanner over the repository."""
    not_available(ctx, "scan", "v0.2")
