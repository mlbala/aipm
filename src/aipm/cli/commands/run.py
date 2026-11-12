"""`aipm run <T-ID>` (v0.3): one attempt loop for one task (ARCHITECTURE §12.4)."""

import typer

from aipm.cli.commands._options import AcceptStale, Budget, DryRun, TaskId, Timeout, Tool
from aipm.cli.commands.build import report
from aipm.cli.output import global_options, handled, print_untrusted, succeed, warn
from aipm.cli.progress import progress_view, show
from aipm.domain.errors import AipmError


def command(
    ctx: typer.Context,
    task_id: TaskId,
    tool: Tool = None,
    timeout: Timeout = None,
    budget: Budget = None,
    dry_run: DryRun = False,
    accept_stale: AcceptStale = False,
) -> None:
    """Dispatch one task to a coding agent and verify the result."""
    opts = global_options(ctx)
    with handled(ctx, "run"):
        from aipm.app import run as use_case

        try:
            with progress_view(json=opts.json) as view:
                result = use_case.run(
                    opts.project, task_id=task_id, tool=tool, timeout=timeout, budget=budget,
                    dry_run=dry_run, accept_stale=accept_stale, no_cache=opts.no_cache,
                    progress=view,
                )  # fmt: skip
        except AipmError as error:
            report(error, json=opts.json)
            raise
        warn(result.warnings)
        data = result.to_data()
        if not opts.json:
            for line in show(data):
                print_untrusted(line)
        succeed(ctx, "run", data)
