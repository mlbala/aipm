"""CLI output helpers: global options, error output, untrusted text and milestone stubs.

aipm's own messages go out through `typer.echo`, never as Rich markup (AGENTS.md rule 8). Text
from an untrusted source, or text that includes repository data, goes through
`print_untrusted`, which sanitizes it and prints it as a Rich `Text`, so neither markup nor
terminal escape sequences can take effect (SECURITY.md §7.10).
"""

import json
import logging
import os
import sys
from collections.abc import Generator, Iterable
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import NoReturn

import typer

from aipm import __version__
from aipm.cli.errors import dumps, envelope, error_envelope
from aipm.domain.errors import AipmError, ExitCode, NotAvailable, NotImplementedYet
from aipm.security.sanitize import sanitize_text

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


def stdin_is_terminal() -> bool:
    """Whether stdin is a terminal (a seam for tests)."""
    return sys.stdin.isatty()


def is_interactive(ctx: typer.Context) -> bool:
    """Prompts are allowed: not `--non-interactive`, `AIPM_NON_INTERACTIVE` or `--json`, and
    stdin is a terminal (ARCHITECTURE §16)."""
    opts = global_options(ctx)
    if opts.non_interactive or opts.json or os.environ.get("AIPM_NON_INTERACTIVE"):
        return False
    return stdin_is_terminal()


def print_untrusted(text: str, *, err: bool = False, source: str = "output") -> None:
    """Sanitize `text` and print it as plain text: no markup, no escapes, no hyperlinks."""
    from rich.console import Console
    from rich.text import Text

    clean = sanitize_text(text, source=source).text
    console = Console(
        stderr=err, highlight=False, emoji=False, markup=False, soft_wrap=True, no_color=True
    )
    console.print(Text(clean), end="\n")


def fail(ctx: typer.Context, command: str, error: AipmError) -> NoReturn:
    """Report `error` and exit with its exit code.

    With `--json`, exactly one envelope goes to stdout. Otherwise the message goes to stderr, and
    the error's machine-readable `data` (such as pending questions) goes to stdout as one JSON
    object, built with `json.dumps` only (SECURITY.md §7.10).
    """
    if global_options(ctx).json:
        typer.echo(dumps(error_envelope(error, command=command, version=__version__)))
    else:
        print_untrusted(f"aipm {command}: {error.message}", err=True)
        if error.hint:
            print_untrusted(f"hint: {error.hint}", err=True)
        if error.data:
            typer.echo(json.dumps(error.data, ensure_ascii=True))
    raise typer.Exit(code=int(error.exit_code))


def succeed(ctx: typer.Context, command: str, data: dict[str, object]) -> None:
    """With `--json`, print the single success envelope (SECURITY.md §7.10: json.dumps only)."""
    if global_options(ctx).json:
        result = envelope(command=command, version=__version__, exit_code=ExitCode.OK, data=data)
        typer.echo(dumps(result))


def warn(messages: Iterable[str]) -> None:
    """Print config warnings to stderr on every run (ARCHITECTURE §15)."""
    for message in messages:
        print_untrusted(f"warning: {message}", err=True)


@contextmanager
def handled(ctx: typer.Context, command: str) -> Generator[None]:
    """Configure logging, then map errors to exit codes.

    An `AipmError` exits with its own code. Anything else is a bug: it is logged (redacted)
    and the command exits 1, pointing at the log file.
    """
    from aipm.app.runtime import configure

    opts = global_options(ctx)
    log_file = configure(opts.verbose, opts.project)
    try:
        yield
    except AipmError as error:
        fail(ctx, command, error)
    except (typer.Exit, typer.Abort, KeyboardInterrupt):
        raise
    except Exception:
        logging.getLogger("aipm").exception("internal error in aipm %s", command)
        where = f"; details are in {log_file}" if log_file else ""
        internal = AipmError(f"internal error (a bug in aipm){where}")
        fail(ctx, command, internal)


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
