"""`aipm merge` (v0.3): fast-forward your branch to the integration branch."""

from typing import Annotated

import typer

from aipm.cli.output import not_available


def command(
    ctx: typer.Context,
    into: Annotated[
        str | None, typer.Option("--into", metavar="BRANCH", help="Branch to fast-forward.")
    ] = None,
) -> None:
    """Fast-forward your branch to the integration branch, after showing the log."""
    not_available(ctx, "merge", "v0.3")
