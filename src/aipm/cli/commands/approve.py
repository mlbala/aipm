"""`aipm approve` (v0.1): non-interactive approval of an artifact (ARCHITECTURE §7.2)."""

from enum import StrEnum
from typing import Annotated

import typer

from aipm.cli.output import not_implemented_yet


class ApproveTarget(StrEnum):
    """Artifacts that can be approved."""

    PRD = "prd"
    DESIGN = "design"
    PLAN = "plan"
    CONTEXT = "context"


def command(
    ctx: typer.Context,
    artifact: Annotated[ApproveTarget, typer.Argument(help="What to approve.")],
    yes: Annotated[
        bool, typer.Option("-y", "--yes", help="Approve without the review prompt.")
    ] = False,
) -> None:
    """Approve the PRD, design, plan or context files non-interactively."""
    not_implemented_yet(ctx, "approve", prompt="03")
