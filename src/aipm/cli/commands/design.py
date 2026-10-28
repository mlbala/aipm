"""`aipm design` (v0.1): architecture, ADRs and threat model."""

from typing import Annotated

import typer

from aipm.cli.commands._options import AcceptRisk, AcceptStale
from aipm.cli.output import not_implemented_yet


def command(
    ctx: typer.Context,
    regenerate: Annotated[
        bool, typer.Option("--regenerate", help="Regenerate from scratch.")
    ] = False,
    accept_risk: AcceptRisk = False,
    accept_stale: AcceptStale = False,
) -> None:
    """Write the architecture, ADRs and threat model."""
    not_implemented_yet(ctx, "design", prompt="04")
