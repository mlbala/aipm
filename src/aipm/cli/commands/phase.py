"""Bare `aipm` (v0.1): the phase report, then an offer to run the next step (ARCHITECTURE §7.3).

Not a registered command: the root callback calls `show` when no command is given.
"""

import typer
from typer.core import TyperGroup

from aipm.cli.output import global_options, handled, is_interactive, print_untrusted, succeed, warn


def _run_next(ctx: typer.Context, command_line: str) -> None:
    """Run one of aipm's own commands, such as `aipm approve plan`, as if typed."""
    words = command_line.split()[1:]
    if not words or not isinstance(ctx.command, TyperGroup):
        return
    sub = ctx.command.get_command(ctx, words[0])
    if sub is None:
        return
    with sub.make_context(words[0], words[1:], parent=ctx) as sub_ctx:
        sub.invoke(sub_ctx)


def show(ctx: typer.Context) -> None:
    """Print the phase report; in an interactive terminal, offer to run `next_command`."""
    opts = global_options(ctx)
    next_command: str | None = None
    with handled(ctx, "aipm"):
        from aipm.app import phase as use_case

        view = use_case.run(opts.project)
        warn(view.warnings)
        if not opts.json:
            for line in view.lines:
                print_untrusted(line)
        succeed(ctx, "aipm", view.to_data())
        next_command = view.report.next_command
    if next_command and is_interactive(ctx):
        if typer.confirm(f"Run `{next_command}` now?", default=False):
            _run_next(ctx, next_command)
