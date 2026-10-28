"""CLI output helpers: global options, error output and milestone stubs.

Text goes out through `typer.echo`, never as Rich markup (AGENTS.md rule 8). Text from an
untrusted source must pass `aipm.security.sanitize` first; the messages here are aipm's own.
"""

from dataclasses import dataclass
from pathlib import Path
from typing import NoReturn

import typer

from aipm import __version__
from aipm.cli.errors import dumps, error_envelope
from aipm.domain.errors import AipmError, NotAvailable, NotImplementedYet

ROADMAP_HINT = "See the roadmap in docs/architecture/ARCHITECTURE.md §22."


@dataclass(frozen=True, slots=True)
class GlobalOptions:
    """The global flags of ARCHITECTURE §16."""

    project: Path | None = None
    json: bool = False
    no_color: bool = False
    non_interactive: bool = False
    yes: bool = False
    verbose: int = 0
    no_plugins: bool = False
    no_cache: bool = False
    trace: bool = False


def global_options(ctx: typer.Context) -> GlobalOptions:
    """Return the global options recorded by the root callback."""
    found = ctx.find_object(GlobalOptions)
    return found if found is not None else GlobalOptions()


def fail(ctx: typer.Context, command: str, error: AipmError) -> NoReturn:
    """Report `error` and exit with its exit code.

    With `--json`, exactly one envelope goes to stdout. Otherwise the message goes to stderr.
    """
    if global_options(ctx).json:
        typer.echo(dumps(error_envelope(error, command=command, version=__version__)))
    else:
        typer.echo(f"aipm {command}: {error.message}", err=True)
        if error.hint:
            typer.echo(f"hint: {error.hint}", err=True)
    raise typer.Exit(code=int(error.exit_code))


def not_available(ctx: typer.Context, command: str, milestone: str) -> NoReturn:
    """Stub for a command from a later milestone: print `available in vX.Y` and exit 2."""
    fail(ctx, command, NotAvailable(f"available in {milestone}", hint=ROADMAP_HINT))


def not_implemented_yet(ctx: typer.Context, command: str, *, prompt: str) -> NoReturn:
    """Stub for a v0.1 command whose build prompt has not run yet; exits 2."""
    fail(
        ctx,
        command,
        NotImplementedYet(
            f"not implemented yet (build prompt {prompt})",
            hint="See docs/prompts/README.md for the build plan.",
        ),
    )
