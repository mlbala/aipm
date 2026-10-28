"""`aipm discover` (v0.1): the requirements interview (ARCHITECTURE §8)."""

from pathlib import Path
from typing import Annotated

import typer

from aipm.cli.commands._options import AcceptRisk
from aipm.cli.output import not_implemented_yet


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
    not_implemented_yet(ctx, "discover", prompt="03")
