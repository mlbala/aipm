"""`aipm discover` (v0.1): the requirements interview (ARCHITECTURE §8)."""

from pathlib import Path
from typing import Annotated

import typer

from aipm.cli.commands._options import AcceptRisk
from aipm.cli.output import global_options, handled, is_interactive, print_untrusted, succeed, warn


def command(
    ctx: typer.Context,
    from_file: Annotated[
        Path | None, typer.Option("--from", metavar="FILE", help="Start from an idea file.")
    ] = None,
    answers: Annotated[
        Path | None, typer.Option("--answers", metavar="FILE", help="Answer questions from a file.")
    ] = None,
    defaults: Annotated[
        bool, typer.Option("--defaults", help="Accept default assumptions for open questions.")
    ] = False,
    edit: Annotated[
        str | None, typer.Option("--edit", metavar="Q-ID", help="Revisit one question.")
    ] = None,
    max_rounds: Annotated[
        int | None, typer.Option("--max-rounds", metavar="N", help="Maximum interview rounds.")
    ] = None,
    threshold: Annotated[
        float | None, typer.Option("--threshold", help="Coverage needed to stop (0-1).")
    ] = None,
    accept_risk: AcceptRisk = False,
) -> None:
    """Interview you for requirements, then write requirements.yaml and the PRD."""
    opts = global_options(ctx)
    with handled(ctx, "discover"):
        from aipm.app import discover as use_case
        from aipm.cli import prompter as prompters

        prompter = prompters.make_prompter() if is_interactive(ctx) else None
        options = use_case.DiscoverOptions(
            from_file=from_file,
            answers=answers,
            defaults=defaults,
            edit=edit,
            max_rounds=max_rounds,
            threshold=threshold,
            accept_risk=accept_risk,
            yes=opts.yes,
        )
        result = use_case.run(opts.project, options=options, prompter=prompter)
        warn(result.warnings)
        if not opts.json:
            print_untrusted(
                f"Coverage {result.score:.2f} (target {result.threshold:.2f}) after "
                f"{result.rounds} rounds; {result.answers} answers, "
                f"{result.assumptions} assumptions, {len(result.open_questions)} open questions."
            )
            print_untrusted(f"Wrote: {', '.join(f'.pm/{name}' for name in result.written)}")
            print_untrusted(f"G1 (PRD approval): {result.approval}")
            for note in result.notes:
                print_untrusted(f"note: {note}")
        succeed(ctx, "discover", result.to_data())
