"""deps: new dependencies exist, are old enough and are no typosquat; osv-scanner on the
changed lockfiles (ARCHITECTURE §13.3, SECURITY.md §12.2).

With no manifest or lockfile changed, the gate passes with "no dependency changes", so
osv-scanner is needed only when dependencies change. A typosquat **fails** the gate (SECURITY.md
§14.3, which wins over the "warning" of §13.3). A registry lookup that fails is an error.
"""

import time
from datetime import datetime

from aipm.domain.models import ChangeStatus, Ecosystem, GateDef, GateFinding, GateStatus, Severity
from aipm.gates.builtin import BuiltinOutcome, outcome, to_findings, tool_missing
from aipm.gates.context import GateContext
from aipm.scanners import osv
from aipm.scanners.base import ScanStatus
from aipm.scanners.registry import RegistryError, first_release
from aipm.security.diff_checks import LOCKFILES, is_manifest, new_dependencies
from aipm.security.supply_chain import age_ok, typosquat_of

NAME = "deps"
_REGISTRY = {Ecosystem.PYPI: "PyPI", Ecosystem.NPM: "npm"}


def _finding(path: str, rule: str, message: str) -> GateFinding:
    return GateFinding(tool="aipm", rule=rule, severity=Severity.HIGH, path=path[:512],
                       message=message[:500])  # fmt: skip


def check_new(ctx: GateContext, now: datetime) -> tuple[list[GateFinding], list[str]]:
    """Registry existence, first-release age and typosquats of every new dependency."""
    findings: list[GateFinding] = []
    errors: list[str] = []
    min_days = ctx.cfg.security.min_dependency_age_days
    for path, eco, name in new_dependencies(ctx.changes):
        squat = typosquat_of(eco, name)
        if squat is not None:
            findings.append(_finding(path, "typosquat", f"{name} is one edit from {squat}"))
        try:
            info = first_release(eco, name, fetch=ctx.fetch)
        except RegistryError as exc:
            errors.append(f"{eco.value} {name}: {exc}")
            continue
        if not info.exists:
            findings.append(_finding(path, "missing", f"{name} does not exist on {_REGISTRY[eco]}"))
        elif info.first_release is not None and not age_ok(
            info.first_release, min_days=min_days, now=now
        ):
            first = info.first_release.date().isoformat()
            message = f"{name} was first released on {first}, less than {min_days} days ago"
            findings.append(_finding(path, "too-new", message))
    return findings, errors


def run(ctx: GateContext, gate: GateDef, *, name: str = NAME, required: bool) -> BuiltinOutcome:
    """Check the dependency changes of the attempt."""
    started = time.monotonic()
    changed = [c for c in ctx.changes.files if is_manifest(c.path)]
    if not changed:
        return outcome(name, GateStatus.PASS, "no dependency changes", required=required,
                       started=started)  # fmt: skip
    findings, errors = check_new(ctx, ctx.now)
    lockfiles = [c.path for c in changed if c.status is not ChangeStatus.DELETED
                 and c.path.rsplit("/", 1)[-1] in LOCKFILES]  # fmt: skip
    output = ""
    if lockfiles:
        scan = osv.scan(ctx.scan_context(), lockfiles)
        output = scan.output
        if scan.status is ScanStatus.SKIPPED:
            return tool_missing(name, scan.reason, required=required, started=started)
        if scan.status is ScanStatus.ERROR:
            errors.append(scan.reason)
        else:
            findings += to_findings(scan.at_least(gate.fail_on or Severity.HIGH))
    if findings:
        summary = f"{len(findings)} dependency problem(s)"
        return outcome(name, GateStatus.FAIL, summary, required=required, started=started,
                       findings=findings, output=output)  # fmt: skip
    if errors:
        return outcome(name, GateStatus.ERROR, "; ".join(errors)[:1000], required=required,
                       started=started, output=output)  # fmt: skip
    return outcome(name, GateStatus.PASS, "new dependencies exist, are old enough and clean",
                   required=required, started=started, output=output)  # fmt: skip
