"""`aipm doctor` (v0.1): tool versions, capabilities, sandbox and which keys are set."""

import typer

from aipm.cli.output import not_implemented_yet


def command(
    ctx: typer.Context,
) -> None:
    """Check tool versions, capabilities, the sandbox and which API keys are set."""
    not_implemented_yet(ctx, "doctor", prompt="02")
