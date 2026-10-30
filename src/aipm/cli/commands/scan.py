"""`aipm scan` (v0.2): every scanner over the whole repository.

Prints each scanner's status and findings (T2, through `print_untrusted`). Exits 3 when a
finding reaches `--fail-on` (default high) or a scanner failed, 8 when the scanner named with
`--scanner` is not installed, and 6 when a config-defined scanner runs on an untrusted surface.
"""

from typing import Annotated

import typer

from aipm.cli.output import global_options, handled, print_untrusted, succeed, warn
from aipm.domain.errors import AipmError


def command(
    ctx: typer.Context,
    scanner: Annotated[
        str | None, typer.Option("--scanner", metavar="NAME", help="Run one scanner only.")
    ] = None,
    fail_on: Annotated[
        str | None,
        typer.Option("--fail-on", metavar="SEVERITY", help="Lowest severity that fails."),
    ] = None,
) -> None:
    """Run every scanner over the repository."""
    opts = global_options(ctx)
    with handled(ctx, "scan"):
        from aipm.app import scan as use_case

        options = use_case.ScanOptions(scanner=scanner, fail_on=fail_on)
        report = use_case.run(opts.project, options)
        warn(report.warnings)
        if not opts.json:
            for result in report.results:
                note = f" ({result.reason})" if result.reason else ""
                print_untrusted(f"{result.tool}: {result.status.value}, "
                                f"{len(result.findings)} finding(s){note}")  # fmt: skip
                for f in result.findings[:20]:
                    line = f":{f.line}" if f.line else ""
                    print_untrusted(f"  - {f.severity.value} {f.rule} {f.path}{line}: {f.message}")
        try:
            use_case.check(report, options)
        except AipmError as error:
            if not opts.json:
                error.data = {}
            raise
        succeed(ctx, "scan", report.to_data())
