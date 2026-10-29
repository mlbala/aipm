"""`aipm doctor` (v0.1): tool versions, capabilities, sandbox and which keys are set."""

import typer

from aipm.cli.output import global_options, handled, print_untrusted, succeed


def command(
    ctx: typer.Context,
) -> None:
    """Check tool versions, capabilities, the sandbox and which API keys are set."""
    opts = global_options(ctx)
    with handled(ctx, "doctor"):
        from aipm.app import doctor as use_case

        report = use_case.run(opts.project)
        if not opts.json:
            for line in report.lines:
                print_untrusted(line)
        succeed(ctx, "doctor", report.data)
