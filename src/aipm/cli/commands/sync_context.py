"""`aipm sync-context` (v0.1): AGENTS.md and CLAUDE.md managed blocks (ARCHITECTURE §10.2)."""

from typing import Annotated

import typer

from aipm.cli.output import not_implemented_yet


def command(
    ctx: typer.Context,
    tool: Annotated[
        list[str] | None, typer.Option("--tool", help="Tool to write context for (repeatable).")
    ] = None,
    check: Annotated[
        bool, typer.Option("--check", help="Exit 3 if the files are out of date.")
    ] = False,
) -> None:
    """Write the managed blocks of AGENTS.md and CLAUDE.md."""
    not_implemented_yet(ctx, "sync-context", prompt="05")
