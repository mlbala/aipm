"""secrets: gitleaks on the changed files, with a regex fallback and a warning (§13.3).

Without gitleaks, aipm's own high-confidence secret patterns (the redactor's, SECURITY.md §8)
scan the same files, and a warning says so. Any finding fails the gate.
"""

import time

from aipm.domain.models import GateFinding, GateStatus, Severity
from aipm.gates.builtin import BuiltinOutcome, outcome, to_findings
from aipm.gates.context import GateContext, changed_files
from aipm.scanners import gitleaks
from aipm.scanners.base import MAX_FILE_BYTES, ScanStatus, read_regular
from aipm.security.redact import Redactor

NAME = "secrets"


def fallback(ctx: GateContext, paths: list[str]) -> list[GateFinding]:
    """Scan the changed files with aipm's own secret patterns, read straight from the tree
    without following a link (nothing is staged in the temp dir, which gates can write)."""
    patterns = Redactor({})
    found: list[GateFinding] = []
    for rel in sorted(set(paths)):
        data = read_regular(ctx.root, rel)
        if data is None:
            continue
        if len(data) > MAX_FILE_BYTES:
            found.append(
                GateFinding(
                    tool="aipm",
                    rule="too-large",
                    severity=Severity.HIGH,
                    path=rel[:512],
                    message="too large for the built-in patterns",
                )
            )
        elif patterns.contains_secret(data.decode("utf-8", errors="replace")):
            found.append(
                GateFinding(tool="aipm", rule="secret-pattern", severity=Severity.HIGH,
                            path=rel[:512], message="matches a known secret format")
            )  # fmt: skip
    return found


def run(ctx: GateContext, *, required: bool) -> BuiltinOutcome:
    """Scan every changed file for secrets."""
    started = time.monotonic()
    paths = changed_files(ctx.changes)
    if not paths:
        return outcome(NAME, GateStatus.PASS, "no changed files to scan", required=required,
                       started=started)  # fmt: skip
    scan = gitleaks.scan(ctx.scan_context(), paths)
    if scan.status is ScanStatus.SKIPPED:
        ctx.warnings.append(f"{scan.reason}; the secrets gate used aipm's built-in patterns")
        found = fallback(ctx, paths)
        tool = "built-in patterns"
    elif scan.status is ScanStatus.ERROR:
        return outcome(NAME, GateStatus.ERROR, scan.reason, required=required, started=started,
                       output=scan.output)  # fmt: skip
    else:
        found = to_findings(scan.findings)
        tool = "gitleaks"
    if found:
        return outcome(NAME, GateStatus.FAIL, f"{tool}: {len(found)} possible secret(s)",
                       required=required, started=started, findings=found,
                       output=scan.output)  # fmt: skip
    return outcome(NAME, GateStatus.PASS, f"{tool}: no secrets in {len(paths)} file(s)",
                   required=required, started=started, output=scan.output)  # fmt: skip
