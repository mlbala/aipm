"""`aipm status` (v0.1): worksheet view and security events; works without an LLM."""

from typing import Annotated

import typer

from aipm.cli.output import global_options, handled, print_untrusted, succeed, warn


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
    opts = global_options(ctx)
    with handled(ctx, "status"):
        from aipm.app import status as use_case

        result = use_case.run(opts.project, show_all=show_all, task_id=task_id, ack=ack)
        warn(result.warnings)
        if not opts.json:
            for line in result.lines:
                print_untrusted(line)
        succeed(ctx, "status", result.to_data())
