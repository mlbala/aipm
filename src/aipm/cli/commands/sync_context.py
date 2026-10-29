"""`aipm sync-context` (v0.1): AGENTS.md and CLAUDE.md managed blocks (ARCHITECTURE §10.2).

Shows a diff of every managed block that would change, then writes them after an interactive
yes, or when `aipm approve context` approved those exact blocks. Without either, a
non-interactive run prints the diff and exits 4. `--check` exits 3 on drift and prints only the
file names. The global `--yes` does not apply: it skips the G1-G3 reviews only.
"""

from typing import Annotated

import typer

from aipm.cli.output import global_options, handled, is_interactive, print_untrusted, succeed, warn
from aipm.domain.errors import HumanInputRequired


def command(
    ctx: typer.Context,
    tool: Annotated[
        list[str] | None, typer.Option("--tool", help="Tool to write context for (repeatable).")
    ] = None,
    check: Annotated[
        bool, typer.Option("--check", help="Exit 3 if the files are out of date.")
    ] = False,
) -> None:
    """Write the managed blocks of AGENTS.md and CLAUDE.md."""
    opts = global_options(ctx)
    tools = tool or []
    with handled(ctx, "sync-context"):
        from aipm.app import sync_context as use_case
        from aipm.cli.review import show_context

        if check:
            files = use_case.check(opts.project, tools)
            if not opts.json:
                print_untrusted(f"Up to date: {', '.join(files)}")
            succeed(ctx, "sync-context", {"up_to_date": list(files), "drift": []})
            return
        review = use_case.review(opts.project, tools)
        warn(review.warnings)
        if not review.changed:
            if not opts.json:
                print_untrusted(f"Up to date: {', '.join(f.path for f in review.files)}")
            succeed(ctx, "sync-context", {**review.to_data(), "written": [], "recorded": []})
            return
        if not opts.json:
            show_context(review)
        approved = all(f.approved for f in review.changed)
        if approved:
            result = use_case.write(opts.project, tools, expected=review.digest, confirmed=False)
        elif is_interactive(ctx):
            if not typer.confirm("Write these managed blocks?", default=False):
                typer.echo("Nothing written.")
                succeed(ctx, "sync-context", {**review.to_data(), "written": [], "recorded": []})
                return
            result = use_case.write(opts.project, tools, expected=review.digest, confirmed=True)
        else:
            raise HumanInputRequired(
                "the managed blocks changed and need your approval",
                hint="Review the diff, then run `aipm approve context --yes` and "
                "`aipm sync-context` again, or run it in a terminal.",
            )
        if not opts.json:
            print_untrusted(f"Wrote: {', '.join(result.written)}")
        succeed(ctx, "sync-context", {**review.to_data(), **result.to_data()})
