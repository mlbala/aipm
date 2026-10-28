"""`aipm task` (v0.2): manual control of task state; every change is recorded."""

from enum import StrEnum
from typing import Annotated

import typer

from aipm.cli.commands._options import TaskId
from aipm.cli.output import not_available


class TaskAction(StrEnum):
    """Manual task actions."""

    SHOW = "show"
    RESET = "reset"
    BLOCK = "block"
    UNBLOCK = "unblock"
    SKIP = "skip"


def command(
    ctx: typer.Context,
    action: Annotated[TaskAction, typer.Argument(help="What to do.")],
    task_id: TaskId,
    reason: Annotated[str | None, typer.Option("--reason", help="Why (recorded).")] = None,
) -> None:
    """Show, reset, block, unblock or skip a task."""
    not_available(ctx, "task", "v0.2")
