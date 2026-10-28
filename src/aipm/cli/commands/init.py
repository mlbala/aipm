"""`aipm init` (v0.1): create `.pm/`, detect the stack, write the repo map, run trust."""

from typing import Annotated

import typer

from aipm.cli.commands._options import Tool
from aipm.cli.output import not_implemented_yet


def command(
    ctx: typer.Context,
    provider: Annotated[
        str | None, typer.Option("--provider", help="LLM provider: anthropic or openai-compatible.")
    ] = None,
    tool: Tool = None,
    stack: Annotated[
        str | None, typer.Option("--stack", help="Stack template, for example python-uv.")
    ] = None,
    force: Annotated[bool, typer.Option("--force", help="Re-initialize an existing .pm/.")] = False,
) -> None:
    """Create .pm/, detect the stack, write the repo map and run the trust flow."""
    not_implemented_yet(ctx, "init", prompt="02")
