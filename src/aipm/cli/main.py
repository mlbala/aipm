"""The `aipm` command line (ARCHITECTURE §16).

Startup must stay fast (`aipm --help` under 300 ms). This module and the command modules
import only Typer and the small CLI helpers; a command loads its use case from `aipm.app`
only when it runs.
"""

from pathlib import Path
from typing import Annotated

import typer

from aipm import __version__
from aipm.cli.commands import (
    approve,
    auto,
    build,
    design,
    discover,
    doctor,
    init,
    merge,
    phase,
    plan,
    prompt,
    run,
    scan,
    status,
    sync_context,
    task,
    trust,
    verify,
)
from aipm.cli.output import GlobalOptions

app = typer.Typer(
    name="aipm",
    help=(
        "An AI product manager for your terminal: requirements interview, design, plan, "
        "prompts for coding agents, and verified builds."
    ),
    add_completion=False,
    # Pretty tracebacks print local variables, which can hold secrets.
    pretty_exceptions_enable=False,
    rich_markup_mode=None,
    context_settings={"help_option_names": ["-h", "--help"]},
)


def _print_version(value: bool) -> None:
    if value:
        typer.echo(f"aipm {__version__}")
        raise typer.Exit


@app.callback(invoke_without_command=True)
def main(
    ctx: typer.Context,
    project: Annotated[
        Path | None,
        typer.Option("-C", "--project", metavar="PATH", help="Run against the repo at PATH."),
    ] = None,
    json_output: Annotated[bool, typer.Option("--json", help="Machine-readable output.")] = False,
    no_color: Annotated[bool, typer.Option("--no-color", help="Disable colour.")] = False,
    non_interactive: Annotated[
        bool,
        typer.Option(
            "--non-interactive",
            help="Never prompt (also set automatically when stdin is not a TTY).",
        ),
    ] = False,
    yes: Annotated[
        bool, typer.Option("-y", "--yes", help="Skip the G1-G3 review gates only.")
    ] = False,
    verbose: Annotated[
        int, typer.Option("-v", "--verbose", count=True, help="More log output.")
    ] = 0,
    no_plugins: Annotated[bool, typer.Option("--no-plugins", help="Do not load plugins.")] = False,
    no_cache: Annotated[
        bool, typer.Option("--no-cache", help="Bypass the LLM response cache (v0.2).")
    ] = False,
    trace: Annotated[
        bool, typer.Option("--trace", help="Emit OpenTelemetry spans (v0.4).")
    ] = False,
    version: Annotated[
        bool,
        typer.Option(
            "--version", callback=_print_version, is_eager=True, help="Print the version."
        ),
    ] = False,
) -> None:
    """With no command: print the phase report and the next step (ARCHITECTURE §7.3)."""
    ctx.obj = GlobalOptions(
        project=project,
        json=json_output,
        no_color=no_color,
        non_interactive=non_interactive,
        yes=yes,
        verbose=verbose,
        no_plugins=no_plugins,
        no_cache=no_cache,
        trace=trace,
    )
    if ctx.invoked_subcommand is None:
        phase.show(ctx)


# Order follows ARCHITECTURE §16.
app.command("init")(init.command)
app.command("doctor")(doctor.command)
app.command("trust")(trust.command)
app.command("discover")(discover.command)
app.command("approve")(approve.command)
app.command("design")(design.command)
app.command("plan")(plan.command)
app.command("status")(status.command)
app.command("prompt")(prompt.command)
app.command("sync-context")(sync_context.command)
app.command("verify")(verify.command)
app.command("scan")(scan.command)
app.command("task")(task.command)
app.command("run")(run.command)
app.command("build")(build.command)
app.command("merge")(merge.command)
app.command("auto")(auto.command)
