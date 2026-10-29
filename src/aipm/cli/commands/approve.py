"""`aipm approve` (v0.1): non-interactive approval of an artifact (ARCHITECTURE §7.2).

Approval is a record in `approvals.yaml`, never trust: `--yes` only skips the review prompt, and
`approve plan --yes` prints the `aipm trust` command to run instead. Only an interactive G3 also
records trust, for the exact surface it showed.
"""

from enum import StrEnum
from typing import Annotated

import typer

from aipm.cli.output import global_options, handled, is_interactive, print_untrusted, succeed
from aipm.domain.errors import HumanInputRequired, PolicyViolation


class ApproveTarget(StrEnum):
    """Artifacts that can be approved."""

    PRD = "prd"
    DESIGN = "design"
    PLAN = "plan"
    CONTEXT = "context"


def _prd(ctx: typer.Context, *, yes: bool) -> None:
    from aipm.app import approve as use_case

    opts = global_options(ctx)
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
    if yes:
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


def _design(ctx: typer.Context, *, yes: bool) -> None:
    from aipm.app import approve as use_case
    from aipm.cli import review as screens

    opts = global_options(ctx)
    review = use_case.review_design(opts.project)
    if not opts.json:
        screens.show_design(review)
    if not yes:
        if not is_interactive(ctx):
            raise HumanInputRequired(
                "approving needs an interactive terminal or --yes",
                hint="Review .pm/architecture.md, .pm/threat-model.md and .pm/adr/, then run "
                "`aipm approve design --yes`.",
            )
        if not screens.ask_design():
            typer.echo("Not approved.")
            succeed(ctx, "approve", {**review.to_data(), "recorded": False})
            return
    copied = use_case.approve_design(opts.project, hashes=review.hashes)
    if not opts.json:
        typer.echo(
            "G2 was already approved for this design." if review.approved else "G2 approved."
        )
        if copied:
            print_untrusted(
                f"Copied the {review.stack_template} stack's prepare step, gates and allowed "
                "commands into .pm/config.yaml. The execution surface changed: review it with "
                "`aipm trust --show` before `aipm plan`."
            )
    succeed(ctx, "approve", {**review.to_data(), "approved": True, "recorded": not review.approved,
                             "stack_copied": copied})  # fmt: skip


def _plan(ctx: typer.Context, *, yes: bool) -> None:
    from aipm.app import approve as use_case
    from aipm.cli import review as screens

    opts = global_options(ctx)
    review = use_case.review_plan(opts.project)
    if not opts.json:
        screens.show_plan(review)
    trust_surface: str | None = None
    if not yes:
        if not is_interactive(ctx):
            raise HumanInputRequired(
                "approving needs an interactive terminal or --yes",
                hint="Review .pm/worksheet.md and `aipm trust --show`, then run "
                "`aipm approve plan --yes`.",
            )
        if review.surface_hash is None:
            raise PolicyViolation(
                f"the execution surface cannot be trusted: {review.surface_error}",
                hint="Fix the gate commands in .pm/config.yaml, then run `aipm approve plan`.",
            )
        if not screens.ask_plan(review):
            typer.echo("Not approved.")
            succeed(ctx, "approve", {**review.to_data(), "recorded": False})
            return
        trust_surface = review.surface_hash
    recorded, trusted = use_case.approve_plan(
        opts.project, sha256=review.sha256, trust_surface=trust_surface
    )
    if not opts.json:
        typer.echo("G3 approved." if recorded else "G3 was already approved for this plan.")
        if trusted:
            typer.echo("The execution surface is trusted.")
        elif review.surface_hash is not None:
            print_untrusted(
                "Trust is not recorded by --yes. Review `aipm trust --show`, then run "
                f"`aipm trust --confirm {review.surface_hash[:12]}`."
            )
        else:
            print_untrusted(f"The execution surface cannot be trusted: {review.surface_error}")
    succeed(ctx, "approve", {**review.to_data(), "approved": True, "recorded": recorded,
                             "trusted": trusted})  # fmt: skip


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
        handler = {ApproveTarget.PRD: _prd, ApproveTarget.DESIGN: _design,
                   ApproveTarget.PLAN: _plan}[artifact]  # fmt: skip
        handler(ctx, yes=yes or opts.yes)
