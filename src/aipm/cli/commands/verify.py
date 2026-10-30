"""`aipm verify <T-ID>` (v0.2): post-change checks and gates for one task.

Needs trust (exit 6). Prints the checks and each gate's status; every line holds repository or
model text, so it goes through `print_untrusted`. A failed verify prints the same view, then
exits 3, 4, 6 or 8 (ARCHITECTURE §16.1); with `--json` the envelope carries it as `data`.
"""

from typing import Annotated, cast

import typer

from aipm.cli.commands._options import AcceptRisk, AcceptStale, TaskId
from aipm.cli.output import global_options, handled, print_untrusted, succeed, warn
from aipm.domain.errors import AipmError


def _records(value: object) -> list[dict[str, object]]:
    """The dict entries of a JSON list (anything else is skipped)."""
    items = cast("list[object]", value) if isinstance(value, list) else []
    return [cast("dict[str, object]", item) for item in items if isinstance(item, dict)]


def _strings(value: object) -> list[str]:
    items = cast("list[object]", value) if isinstance(value, list) else []
    return [str(item) for item in items]


def show(data: dict[str, object]) -> None:
    """Print a verify result (from its JSON data) for a human."""
    print_untrusted(
        f"{data.get('task')}: {data.get('outcome')} (attempt {data.get('attempt')}, run "
        f"{data.get('run_id')}, base {str(data.get('base_sha'))[:12]})"
    )
    for item in _records(data.get("violations")):
        print_untrusted(
            f"  {item.get('level')}: {item.get('kind')}: {item.get('path')}: {item.get('detail')}"
        )
    for gate in _records(data.get("gates")):
        required = " (required)" if gate.get("required") else ""
        print_untrusted(
            f"  {gate.get('name')}: {gate.get('status')}{required}: {gate.get('summary')}"
        )
        for finding in _records(gate.get("findings"))[:10]:
            where = str(finding.get("path") or "")
            line = f":{finding.get('line')}" if finding.get("line") else ""
            print_untrusted(f"    - {finding.get('rule')} {where}{line}: {finding.get('message')}")
    if data.get("commit"):
        print_untrusted(f"Committed {str(data.get('commit'))[:12]}.")
    if data.get("report"):
        print_untrusted(f"Saved {data.get('report')}.")
    if not data.get("sandboxed"):
        print_untrusted("Gates ran without a sandbox.")


def command(
    ctx: typer.Context,
    task_id: TaskId,
    commit: Annotated[
        bool, typer.Option("--commit", help="Commit the result with aipm trailers.")
    ] = False,
    base: Annotated[
        str | None, typer.Option("--base", metavar="SHA", help="Diff from this commit.")
    ] = None,
    gate: Annotated[
        str | None, typer.Option("--gate", metavar="NAME", help="Run one gate only.")
    ] = None,
    override_ac: Annotated[
        str | None,
        typer.Option(
            "--override-ac", metavar="ID", help="Override an acceptance-criterion veto (logged)."
        ),
    ] = None,
    reason: Annotated[
        str | None, typer.Option("--reason", help="Why the override is justified.")
    ] = None,
    accept_risk: AcceptRisk = False,
    accept_stale: AcceptStale = False,
) -> None:
    """Run the post-change checks and every gate for one task."""
    opts = global_options(ctx)
    with handled(ctx, "verify"):
        from aipm.app import verify as use_case

        options = use_case.VerifyOptions(
            task_id=task_id,
            commit=commit,
            base=base,
            gate=gate,
            override_ac=override_ac,
            reason=reason,
            accept_risk=accept_risk,
            accept_stale=accept_stale,
            no_cache=opts.no_cache,
        )
        try:
            result = use_case.run(opts.project, options)
        except AipmError as error:
            if not opts.json and "gates" in error.data:
                warn(_strings(error.data.get("warnings")))
                show(error.data)
                error.data = {}
            raise
        warn(result.warnings)
        data = result.to_data()
        if not opts.json:
            show(data)
        succeed(ctx, "verify", data)
