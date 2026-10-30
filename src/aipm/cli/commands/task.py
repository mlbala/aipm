"""`aipm task` (v0.2): manual control of task state; every change is recorded.

`show` prints the task (its titles and criteria are model-written, so through
`print_untrusted`); the other actions print the change. `block` needs `--reason`.
"""

from enum import StrEnum
from typing import Annotated

import typer

from aipm.cli.commands._options import TaskId
from aipm.cli.output import global_options, handled, print_untrusted, succeed


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
    opts = global_options(ctx)
    with handled(ctx, "task"):
        from aipm.app import task as use_case

        result = use_case.run(opts.project, action=action.value, task_id=task_id, reason=reason)
        data = result.to_data()
        if not opts.json:
            task = result.task
            if action is TaskAction.SHOW:
                print_untrusted(f"{task.id}: {task.title}")
                print_untrusted(f"  status: {task.status.value}, attempts: {task.attempts}")
                if task.base_sha:
                    print_untrusted(f"  base: {task.base_sha[:12]}, attempt snapshot: "
                                    f"{'yes' if result.snapshot else 'no'}")  # fmt: skip
                if task.blocked is not None:
                    print_untrusted(f"  blocked: {task.blocked.reason.value}: "
                                    f"{task.blocked.detail}")  # fmt: skip
                if task.done is not None:
                    print_untrusted(f"  done: {task.done.commit or 'not committed'}")
                print_untrusted(f"  owns: {', '.join(task.owns_files) or '(nothing)'}")
                print_untrusted(f"  gates: {', '.join(task.gates) or '(none)'}")
                for criterion in task.acceptance:
                    print_untrusted(f"  {criterion.id}: {criterion.text}")
            else:
                print_untrusted(f"{task.id}: {result.previous.value} -> {task.status.value} "
                                f"({action.value}, recorded in .pm/approvals.yaml)")  # fmt: skip
        succeed(ctx, "task", data)
