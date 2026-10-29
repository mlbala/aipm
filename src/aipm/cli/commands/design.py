"""`aipm design` (v0.1): architecture, ADRs and threat model, then G2 (ARCHITECTURE §14.1)."""

from typing import Annotated

import typer

from aipm.cli.commands._options import AcceptRisk, AcceptStale
from aipm.cli.output import global_options, handled, is_interactive, print_untrusted, succeed, warn


def command(
    ctx: typer.Context,
    regenerate: Annotated[
        bool, typer.Option("--regenerate", help="Regenerate from scratch.")
    ] = False,
    accept_risk: AcceptRisk = False,
    accept_stale: AcceptStale = False,
) -> None:
    """Write the architecture, ADRs and threat model."""
    opts = global_options(ctx)
    with handled(ctx, "design"):
        from aipm.app import design as use_case
        from aipm.cli.review import ReviewPrompter

        prompter = ReviewPrompter() if is_interactive(ctx) else None
        options = use_case.DesignOptions(
            regenerate=regenerate, accept_risk=accept_risk, accept_stale=accept_stale,
            yes=opts.yes,
        )  # fmt: skip
        result = use_case.run(opts.project, options=options, prompter=prompter)
        warn(result.warnings)
        if not opts.json:
            if result.generated:
                print_untrusted(f"Wrote: {', '.join(f'.pm/{n}' for n in result.written)}")
            review = result.review
            print_untrusted(
                f"Design: {review.stack_template}, {len(review.components)} components, "
                f"{len(review.adrs)} ADRs, {len(review.threats)} threats of medium or higher"
            )
            print_untrusted(f"G2 (design approval): {result.approval}")
            for note in result.notes:
                print_untrusted(f"note: {note}")
        succeed(ctx, "design", result.to_data())
