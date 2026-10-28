"""`aipm prompt <T-ID>` (v0.1): the compiled task prompt; needs trust (SECURITY.md §6)."""

from pathlib import Path
from typing import Annotated

import typer

from aipm.cli.commands._options import AcceptStale, TaskId, Tool
from aipm.cli.output import not_implemented_yet


def command(
    ctx: typer.Context,
    task_id: TaskId,
    tool: Tool = None,
    copy: Annotated[
        bool, typer.Option("--copy", help="Also copy the prompt to the clipboard.")
    ] = False,
    out: Annotated[
        Path | None, typer.Option("--out", metavar="FILE", help="Write the prompt to a file.")
    ] = None,
    fix: Annotated[
        bool, typer.Option("--fix", help="Prompt for fixing the last failed verify.")
    ] = False,
    accept_stale: AcceptStale = False,
) -> None:
    """Print the prompt for a task, for your own coding agent."""
    not_implemented_yet(ctx, "prompt", prompt="05")
