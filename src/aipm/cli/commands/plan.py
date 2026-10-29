"""`aipm plan` (v0.1): the task graph (ARCHITECTURE §9), `tasks.yaml`, `worksheet.md` and G3."""

from typing import Annotated

import typer

from aipm.cli.commands._options import AcceptRisk, AcceptStale
from aipm.cli.output import global_options, handled, is_interactive, print_untrusted, succeed, warn


def _count(n: int, noun: str) -> str:
    return f"{n} {noun}" if n == 1 else f"{n} {noun}s"


def command(
    ctx: typer.Context,
    max_tasks: Annotated[
        int | None, typer.Option("--max-tasks", metavar="N", help="Maximum number of tasks.")
    ] = None,
    accept_risk: AcceptRisk = False,
    accept_stale: AcceptStale = False,
) -> None:
    """Split the work into a task graph with acceptance criteria and gates."""
    opts = global_options(ctx)
    with handled(ctx, "plan"):
        from aipm.app import plan as use_case
        from aipm.cli.review import ReviewPrompter

        prompter = ReviewPrompter() if is_interactive(ctx) else None
        options = use_case.PlanOptions(
            max_tasks=max_tasks, accept_risk=accept_risk, accept_stale=accept_stale, yes=opts.yes
        )
        result = use_case.run(opts.project, options=options, prompter=prompter)
        warn(result.warnings)
        if not opts.json:
            facts = result.review.facts
            print_untrusted(f"Wrote: {', '.join(f'.pm/{n}' for n in result.written)}")
            print_untrusted(
                f"Plan: {result.tasks} tasks, DAG depth {facts.depth}, widest level "
                f"{facts.width}; {_count(len(result.changes), 'change')} by the plan validator"
            )
            print_untrusted(f"G3 (plan approval): {result.approval}")
            print_untrusted(f"Execution surface trusted: {'yes' if result.trusted else 'no'}")
            for note in result.notes:
                print_untrusted(f"note: {note}")
        succeed(ctx, "plan", result.to_data())
