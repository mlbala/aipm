"""`aipm init` (v0.1): create `.pm/`, detect the stack, write the repo map, run trust."""

from pathlib import Path
from typing import Annotated

import typer

from aipm.cli.commands._options import Tool
from aipm.cli.output import global_options, handled, is_interactive, print_untrusted, succeed, warn


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
    opts = global_options(ctx)
    with handled(ctx, "init"):
        from aipm.app import init as use_case
        from aipm.app import trust as trust_use_case

        result = use_case.run(opts.project, provider=provider, tool=tool, stack=stack, force=force)
        warn(result.warnings)
        if not opts.json:
            print_untrusted(f"Initialized .pm/ in {result.repo_root} ({result.mode.value})")
            print_untrusted(f"Stack template: {result.stack_template or 'none'}")
            print_untrusted(f"Wrote: {', '.join(result.written)}")
            if result.kept:
                print_untrusted(f"Kept: {', '.join(result.kept)}")
            for note in result.notes:
                print_untrusted(f"note: {note}")
        trusted = False
        if result.trust is not None:
            trusted = result.trust.trusted
            hash12 = result.trust.surface_hash[:12]
            if not opts.json:
                typer.echo("")
                for line in result.trust.lines:
                    print_untrusted(line)
            if not trusted and is_interactive(ctx):
                if typer.confirm(
                    "Trust this execution surface for this repository?", default=False
                ):
                    trusted = trust_use_case.confirm(Path(result.repo_root), hash12).trusted
                    typer.echo("Trusted.")
                else:
                    typer.echo("Not trusted. Run `aipm trust` when you are ready.")
            elif not trusted and not opts.json:
                typer.echo(
                    f"Not trusted yet. After reviewing it, run: aipm trust --confirm {hash12}"
                )
        succeed(ctx, "init", {**result.to_data(), "trusted": trusted})
