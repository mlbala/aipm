"""`aipm build` (v0.3): every ready task, in parallel where safe (ARCHITECTURE §12).

Live progress goes to stderr; the end-of-run summary to stdout (or the JSON envelope). A build
that stopped early prints the same summary, then exits 3, 5, 6 or 130 (ARCHITECTURE §16.1).
"""

from typing import cast

import typer

from aipm.cli.commands._options import (
    AcceptStale,
    Budget,
    DryRun,
    MaxRetries,
    Only,
    Parallel,
    Timeout,
    Tool,
)
from aipm.cli.output import global_options, handled, print_untrusted, succeed, warn
from aipm.cli.progress import progress_view, show
from aipm.domain.errors import AipmError


def report(error: AipmError, *, json: bool) -> None:
    """Print a stopped build's summary for a human, and keep the message for stderr."""
    if not json and "tasks" in error.data:
        warn(cast("list[str]", error.data.get("warnings") or []))
        for line in show(error.data):
            print_untrusted(line)
        error.data = {}


def command(
    ctx: typer.Context,
    tool: Tool = None,
    parallel: Parallel = None,
    max_retries: MaxRetries = None,
    budget: Budget = None,
    timeout: Timeout = None,
    only: Only = None,
    dry_run: DryRun = False,
    accept_stale: AcceptStale = False,
) -> None:
    """Build every ready task with coding agents, verifying each one."""
    opts = global_options(ctx)
    with handled(ctx, "build"):
        from aipm.app import build as use_case

        options = use_case.BuildOptions(
            kind="build", tool=tool, parallel=parallel, max_retries=max_retries, budget=budget,
            timeout=timeout, only=only, dry_run=dry_run, accept_stale=accept_stale,
            no_cache=opts.no_cache,
        )  # fmt: skip
        try:
            with progress_view(json=opts.json) as view:
                result = use_case.run(opts.project, options, progress=view)
        except AipmError as error:
            report(error, json=opts.json)
            raise
        warn(result.warnings)
        data = result.to_data()
        if not opts.json:
            for line in show(data):
                print_untrusted(line)
        succeed(ctx, "build", data)
