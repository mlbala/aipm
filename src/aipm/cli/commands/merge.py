"""`aipm merge` (v0.3): fast-forward your branch to the integration branch.

Shows `git log --oneline <branch>..aipm/integration` (repository text, printed through
`print_untrusted`), asks for confirmation, then fast-forwards. A non-interactive run exits 4: a
branch of yours never moves without a person's yes (`--yes` covers only the G1-G3 reviews).
"""

from typing import Annotated

import typer

from aipm.cli.output import global_options, handled, is_interactive, print_untrusted, succeed, warn
from aipm.domain.errors import HumanInputRequired


def command(
    ctx: typer.Context,
    into: Annotated[
        str | None, typer.Option("--into", metavar="BRANCH", help="Branch to fast-forward.")
    ] = None,
) -> None:
    """Fast-forward your branch to the integration branch, after showing the log."""
    opts = global_options(ctx)
    with handled(ctx, "merge"):
        from aipm.app import merge as use_case

        shown = use_case.plan(opts.project, into=into)
        warn(shown.warnings)
        if shown.nothing:
            if not opts.json:
                print_untrusted(
                    f"{shown.target} is already at {shown.integration}; nothing to merge."
                )
            succeed(ctx, "merge", shown.to_data())
            return
        if not opts.json:
            print_untrusted(
                f"{len(shown.lines)} commit(s) on {shown.integration} not on {shown.target}:"
            )
            for line in shown.lines:
                print_untrusted(f"  {line}")
            if shown.more:
                print_untrusted("  … and more")
        if not is_interactive(ctx):
            raise HumanInputRequired(
                f"aipm merge moves {shown.target} only after you confirm",
                hint="Run `aipm merge` in a terminal and review the log.",
                data=shown.to_data(),
            )
        if not typer.confirm(f"Fast-forward {shown.target} to {shown.integration}?", default=False):
            print_untrusted("Nothing merged.")
            succeed(ctx, "merge", {**shown.to_data(), "merged": False})
            return
        result = use_case.apply(opts.project, shown)
        if not opts.json:
            print_untrusted(
                f"{result.target} is now at {result.after[:12]} ({result.commits} commit(s))."
            )
        succeed(ctx, "merge", result.to_data())
