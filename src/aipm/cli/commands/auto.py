"""`aipm auto` (v0.4): run the next step until built; never records trust (§7.3, ADR-0028).

Each step runs through the same command function a person would type, so it prompts, prints and
checks exactly as that command does. With `--json`, the steps' own output goes to stderr and
stdout carries one envelope for the whole run.
"""

import sys
from collections.abc import Generator
from contextlib import contextmanager, redirect_stdout
from dataclasses import dataclass, replace
from typing import TYPE_CHECKING, Annotated

import typer

from aipm.cli.commands import approve, build, design, discover, plan
from aipm.cli.commands._options import (
    AcceptRisk,
    AcceptStale,
    Budget,
    DryRun,
    MaxRetries,
    Only,
    Parallel,
    Timeout,
    Tool,
)
from aipm.cli.output import GlobalOptions, global_options, handled, is_interactive, succeed

if TYPE_CHECKING:
    from aipm.app.auto import AutoStep


@dataclass(frozen=True, slots=True)
class _Flags:
    accept_risk: bool
    accept_stale: bool
    tool: str | None
    parallel: int | None
    max_retries: int | None
    budget: float | None
    timeout: str | None
    only: str | None
    dry_run: bool


class _Steps:
    """Runs each step through its own command, with the global options of this run."""

    def __init__(self, ctx: typer.Context, flags: _Flags) -> None:
        self.ctx = ctx
        self.flags = flags
        self.opts = global_options(ctx)

    @contextmanager
    def _as_step(self) -> Generator[None]:
        """The step sees `--json` off; with `--json`, its output goes to stderr."""
        self.ctx.obj = replace(self.opts, json=False)
        try:
            if self.opts.json:
                with redirect_stdout(sys.stderr):
                    yield
            else:
                yield
        finally:
            self.ctx.obj = self.opts

    def run(self, step: "AutoStep", *, yes: bool) -> None:
        from aipm.app import auto as use_case

        f = self.flags
        if not self.opts.json:
            typer.echo(f"==> {step.command}")
        try:
            with self._as_step():
                if step.name == "discover":
                    discover.command(self.ctx, accept_risk=f.accept_risk)
                elif step.name == "design":
                    design.command(
                        self.ctx,
                        regenerate=step.arg == "--regenerate",
                        accept_risk=f.accept_risk,
                        accept_stale=f.accept_stale,
                    )
                elif step.name == "plan":
                    plan.command(self.ctx, accept_risk=f.accept_risk, accept_stale=f.accept_stale)
                elif step.name == "approve":
                    approve.command(self.ctx, approve.ApproveTarget(step.arg), yes=yes)
                else:  # build: next_step names nothing else
                    build.command(
                        self.ctx, tool=f.tool, parallel=f.parallel, max_retries=f.max_retries,
                        budget=f.budget, timeout=f.timeout, only=f.only, dry_run=f.dry_run,
                        accept_stale=f.accept_stale,
                    )  # fmt: skip
        except typer.Exit as stopped:
            if stopped.exit_code:
                raise use_case.step_failed(int(stopped.exit_code), step.command) from None


def command(
    ctx: typer.Context,
    yes: Annotated[
        bool, typer.Option("-y", "--yes", help="Skip the G1-G3 review gates only.")
    ] = False,
    accept_risk: AcceptRisk = False,
    accept_stale: AcceptStale = False,
    tool: Tool = None,
    parallel: Parallel = None,
    max_retries: MaxRetries = None,
    budget: Budget = None,
    timeout: Timeout = None,
    only: Only = None,
    dry_run: DryRun = False,
) -> None:
    """Run every step in order, pausing at the review gates."""
    opts: GlobalOptions = global_options(ctx)
    with handled(ctx, "auto"):
        from aipm.app import auto as use_case

        flags = _Flags(accept_risk, accept_stale, tool, parallel, max_retries, budget, timeout,
                       only, dry_run)  # fmt: skip
        if yes and not opts.yes:
            ctx.obj = replace(opts, yes=True)
        options = use_case.AutoOptions(
            yes=yes or opts.yes,
            interactive=is_interactive(ctx),
            one_build=dry_run or only is not None,
        )
        result = use_case.run(opts.project, options, _Steps(ctx, flags))
        if not opts.json:
            typer.echo(f"aipm auto: done ({result.phase}); ran {len(result.ran)} steps.")
        succeed(ctx, "auto", result.to_data())
