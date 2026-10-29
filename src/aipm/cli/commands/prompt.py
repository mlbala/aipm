"""`aipm prompt <T-ID>` (v0.1): the compiled task prompt; needs trust (SECURITY.md §6).

The prompt goes to stdout, alone, so `aipm prompt T-001 > prompt.md` captures exactly the text
saved in `.pm/prompts/`; aipm's own messages go to stderr. The prompt holds repository and model
text, so it is printed through `print_untrusted` (no markup, no escapes).
"""

from pathlib import Path
from typing import Annotated

import typer

from aipm.cli.commands._options import AcceptStale, TaskId, Tool
from aipm.cli.output import global_options, handled, print_untrusted, succeed, warn


def command(
    ctx: typer.Context,
    task_id: TaskId,
    tool: Tool = None,
    copy: Annotated[
        bool, typer.Option("--copy", help="Also copy the prompt to the clipboard.")
    ] = False,
    out: Annotated[
        Path | None,
        typer.Option("--out", metavar="FILE", help="Write the prompt to a file in the repo."),
    ] = None,
    fix: Annotated[
        bool, typer.Option("--fix", help="Prompt for fixing the last failed verify.")
    ] = False,
    report: Annotated[
        Path | None,
        typer.Option(
            "--report", metavar="FILE", help="The saved gate report to fix (with --fix; v0.1)."
        ),
    ] = None,
    force: Annotated[
        bool, typer.Option("--force", help="Start even if its dependencies are not done.")
    ] = False,
    accept_stale: AcceptStale = False,
) -> None:
    """Print the prompt for a task, for your own coding agent."""
    opts = global_options(ctx)
    with handled(ctx, "prompt"):
        from aipm.app import prompt as use_case

        options = use_case.PromptOptions(
            task_id=task_id,
            tool=tool,
            copy=copy,
            out=out,
            fix=fix,
            report=report,
            force=force,
            accept_stale=accept_stale,
        )
        result = use_case.run(opts.project, options)
        warn(result.warnings)
        if not opts.json:
            if result.out is None:
                print_untrusted(result.text.rstrip("\n"))
            print_untrusted(
                f"Saved {result.file}"
                + (f" and {result.out}" if result.out else "")
                + f"; {result.task_id} is in progress from {result.base_sha[:12]}.",
                err=True,
            )
            if result.omitted:
                print_untrusted(
                    f"note: left out {', '.join(result.omitted)} (24 KiB budget)", err=True
                )
            if result.copy_requested:
                print_untrusted(
                    f"Copied with {result.copied_with}."
                    if result.copied_with
                    else "No clipboard tool worked (pbcopy, wl-copy or xclip); copy the prompt "
                    "from the output or the saved file.",
                    err=True,
                )
        succeed(ctx, "prompt", result.to_data())
