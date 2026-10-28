"""`aipm trust` (v0.1): show the execution surface and record trust (SECURITY.md §6)."""

from typing import Annotated

import typer

from aipm.cli.output import not_implemented_yet


def command(
    ctx: typer.Context,
    show: Annotated[bool, typer.Option("--show", help="Show the execution surface only.")] = False,
    revoke: Annotated[
        bool, typer.Option("--revoke", help="Revoke trust for this repository.")
    ] = False,
    confirm: Annotated[
        str | None,
        typer.Option(
            "--confirm",
            metavar="HASH12",
            help="Trust non-interactively; must match the surface hash prefix.",
        ),
    ] = None,
) -> None:
    """Show the exact commands aipm may run, then record your trust in them."""
    not_implemented_yet(ctx, "trust", prompt="02")
