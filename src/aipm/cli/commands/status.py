"""`aipm status` (v0.1): worksheet view and security events; works without an LLM."""

from typing import Annotated

import typer

from aipm.cli.output import not_implemented_yet


def command(
    ctx: typer.Context,
    show_all: Annotated[bool, typer.Option("--all", help="Show every task.")] = False,
    task_id: Annotated[
        str | None, typer.Option("--task", metavar="T-ID", help="Show one task.")
    ] = None,
    ack: Annotated[
        str | None, typer.Option("--ack", metavar="EVENT-ID", help="Acknowledge a security event.")
    ] = None,
) -> None:
    """Show task status and security events."""
    not_implemented_yet(ctx, "status", prompt="04")
