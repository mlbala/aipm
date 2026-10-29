"""`aipm approve` (v0.1): non-interactive approval of an artifact (ARCHITECTURE §7.2).

Approval is a record in `approvals.yaml`, never trust: `--yes` only skips the review prompt.
"""

from enum import StrEnum
from typing import Annotated

import typer

from aipm.cli.output import global_options, handled, is_interactive, print_untrusted, succeed
from aipm.domain.errors import HumanInputRequired


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
    opts = global_options(ctx)
    with handled(ctx, "approve"):
        from aipm.app import approve as use_case

        use_case.check_target(artifact.value)
        review = use_case.review_prd(opts.project)
        if not opts.json:
            print_untrusted(f"PRD: .pm/prd.md (sha256 {review.sha256[:12]})")
            if review.one_liner:
                print_untrusted(review.one_liner)
            for title, lines in (
                ("Features", review.features),
                ("Non-functional requirements", review.non_functional),
                ("Assumptions", review.assumptions),
                ("Open questions", review.open_questions),
            ):
                print_untrusted(f"{title}:")
                for line in lines or ("(none)",):
                    print_untrusted(f"  - {line}")
        if yes or opts.yes:
            recorded = use_case.approve_prd(opts.project, sha256=review.sha256)
        elif is_interactive(ctx):
            if not typer.confirm("Approve the PRD (G1)?", default=False):
                typer.echo("Not approved.")
                succeed(ctx, "approve", {**review.to_data(), "recorded": False})
                return
            recorded = use_case.approve_prd(opts.project, sha256=review.sha256)
        else:
            raise HumanInputRequired(
                "approving needs an interactive terminal or --yes",
                hint="Review .pm/prd.md, then run `aipm approve prd --yes`.",
            )
        if not opts.json:
            typer.echo("G1 approved." if recorded else "G1 was already approved for this PRD.")
        succeed(ctx, "approve", {**review.to_data(), "approved": True, "recorded": recorded})
