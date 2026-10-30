"""sast: semgrep with pinned rule packs and `--metrics off`, on the owned files (§13.3).

`--config auto` is never used: the packs come from `scanners.semgrep.configs`. Findings at the
gate's `fail_on` severity (default high) or above fail it; lower ones are listed.
"""

import time

from aipm.domain.models import GateDef, GateStatus, Severity
from aipm.gates.builtin import BuiltinOutcome, outcome, to_findings, tool_missing
from aipm.gates.context import GateContext, owned_files
from aipm.scanners import semgrep
from aipm.scanners.base import ScanStatus

NAME = "sast"


def run(ctx: GateContext, gate: GateDef, *, name: str = NAME, required: bool) -> BuiltinOutcome:
    """Run semgrep over the task's files."""
    started = time.monotonic()
    files = [p for p in owned_files(ctx.root, ctx.task) if not p.startswith(".pm/")]
    if not files:
        return outcome(name, GateStatus.PASS, "no owned files to scan", required=required,
                       started=started)  # fmt: skip
    scan = semgrep.scan(ctx.scan_context(), files, configs=ctx.cfg.scanners.semgrep.configs)
    if scan.status is ScanStatus.SKIPPED:
        return tool_missing(name, scan.reason, required=required, started=started)
    if scan.status is ScanStatus.ERROR:
        return outcome(name, GateStatus.ERROR, scan.reason, required=required, started=started,
                       output=scan.output)  # fmt: skip
    level = gate.fail_on or Severity.HIGH
    blocking = scan.at_least(level)
    findings = to_findings(sorted(scan.findings, key=lambda f: f not in blocking))
    if blocking:
        summary = f"{len(blocking)} finding(s) at {level.value} or above"
        return outcome(name, GateStatus.FAIL, summary, required=required, started=started,
                       findings=findings, output=scan.output)  # fmt: skip
    summary = f"no findings at {level.value} or above ({len(scan.findings)} lower)"
    return outcome(name, GateStatus.PASS, summary, required=required, started=started,
                   findings=findings, output=scan.output)  # fmt: skip
