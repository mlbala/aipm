"""`aipm trust` (v0.1): show the execution surface and record trust (SECURITY.md §6).

Trust is recorded after an interactive "yes", or non-interactively only with `--confirm` and
the first 12 hex characters of the surface hash. The global `--yes` is never read here.
"""

from typing import Annotated

import typer

from aipm.cli.output import global_options, handled, is_interactive, print_untrusted, succeed, warn
from aipm.domain.errors import HumanInputRequired


def command(
    ctx: typer.Context,
    show: Annotated[bool, typer.Option("--show", help="Show the execution surface only.")] = False,
    revoke: Annotated[
        bool, typer.Option("--revoke", help="Revoke trust for this repository.")
    ] = False,
    confirm: Annotated[
        str | None,
        typer.Option(
            "--confirm",
            metavar="HASH12",
            help="Trust non-interactively; must match the surface hash prefix.",
        ),
    ] = None,
) -> None:
    """Show the exact commands aipm may run, then record your trust in them."""
    opts = global_options(ctx)
    with handled(ctx, "trust"):
        from aipm.app import trust as use_case

        if revoke:
            removed = use_case.revoke(opts.project)
            if not opts.json:
                typer.echo("Trust revoked." if removed else "This repository was not trusted.")
            succeed(ctx, "trust", {"revoked": removed})
            return
        context = use_case.load(opts.project)
        warn(context.warnings)
        report = use_case.inspect(context)
        if not opts.json:
            for line in report.lines:
                print_untrusted(line)
            typer.echo(f"trusted: {'yes' if report.trusted else 'no'}")
        if show:
            succeed(ctx, "trust", report.to_data())
            return
        hash12 = report.surface_hash[:12]
        if confirm is not None:
            report = use_case.confirm(opts.project, confirm)
        elif report.trusted:
            pass
        elif is_interactive(ctx):
            if typer.confirm("Trust this exact surface for this repository?", default=False):
                report = use_case.confirm(opts.project, report.surface_hash)
        else:
            raise HumanInputRequired(
                "recording trust needs interactive confirmation or --confirm",
                hint=f"Review the surface above, then run `aipm trust --confirm {hash12}`.",
            )
        if not opts.json:
            typer.echo("This surface is trusted." if report.trusted else "Not trusted.")
        succeed(ctx, "trust", report.to_data())
