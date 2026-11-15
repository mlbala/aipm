"""deps: new dependencies exist, are old enough and are no typosquat; osv-scanner on the
changed lockfiles (ARCHITECTURE §13.3, SECURITY.md §12.2).

With no manifest or lockfile changed, the gate passes with "no dependency changes", so
osv-scanner is needed only when dependencies change. A package that only a lockfile adds (a
transitive one, or one a task slipped in beside its declared dependency) is looked up too: it
must exist and be old enough (red-team v0.2, RT02-3). The typosquat check stays on the names a
manifest declares: upstream maintainers choose transitive names, so it would flag them wrongly.
A typosquat **fails** the gate (SECURITY.md §14.3, which wins over the "warning" of §13.3). A
registry lookup that fails is an error.
"""

import time
from dataclasses import dataclass, field
from datetime import datetime

from aipm.domain.errors import PolicyViolation
from aipm.domain.models import ChangeStatus, Ecosystem, GateDef, GateFinding, GateStatus, Severity
from aipm.gates.builtin import BuiltinOutcome, outcome, to_findings, tool_missing
from aipm.gates.context import GateContext
from aipm.scanners import osv
from aipm.scanners.base import ScanStatus
from aipm.scanners.registry import (
    RegistryError,
    RegistryUnavailable,
    first_release,
    go_version_cached,
)
from aipm.security.diff_checks import (
    LOCKFILES,
    is_manifest,
    new_dependencies,
    new_go_requirements,
    new_lock_packages,
)
from aipm.security.supply_chain import age_ok, edit_distance, normalize_name, typosquat_of

NAME = "deps"
MAX_LOOKUPS = 500
"""Registry lookups per attempt; more new packages than this is an error, never a pass."""
DEPS_BUDGET_S = 300.0
"""The most all of one attempt's registry lookups may take together; each is bounded by
`registry.DEADLINE_S` (red-team v0.4, RT04-14). The packages not looked up are an error."""
_clock = time.monotonic
_REGISTRY = {
    Ecosystem.PYPI: "PyPI",
    Ecosystem.NPM: "npm",
    Ecosystem.GO: "the Go module proxy",
    Ecosystem.CRATES: "crates.io",
}


def _finding(path: str, rule: str, message: str) -> GateFinding:
    return GateFinding(tool="aipm", rule=rule, severity=Severity.HIGH, path=path[:512],
                       message=message[:500])  # fmt: skip


def _to_check(ctx: GateContext) -> list[tuple[str, Ecosystem, str, bool]]:
    """(path, ecosystem, name, direct) for every new package: manifests first, then lockfiles."""
    seen: set[tuple[Ecosystem, str]] = set()
    found: list[tuple[str, Ecosystem, str, bool]] = []
    for direct, items in ((True, new_dependencies(ctx.changes)),
                          (False, new_lock_packages(ctx.changes))):  # fmt: skip
        for path, eco, name in items:
            if (eco, name) not in seen:
                seen.add((eco, name))
                found.append((path, eco, name, direct))
    return found


def new_go_modules(ctx: GateContext) -> bool:
    """Whether the attempt adds a Go module (to `go.mod` or `go.sum`), or a new version of one
    to `go.mod`."""
    return bool(new_go_requirements(ctx.changes)) or any(
        eco is Ecosystem.GO for _, eco, _, _ in _to_check(ctx)
    )


@dataclass(slots=True)
class _Checked:
    findings: list[GateFinding] = field(default_factory=list[GateFinding])
    errors: list[tuple[str, str]] = field(default_factory=list[tuple[str, str]])
    """(path, why) for each package whose lookup gave an answer aipm cannot judge."""
    unavailable: list[str] = field(default_factory=list[str])
    """Why each lookup that got no answer at all failed (`RegistryUnavailable`)."""
    flagged: set[str] = field(default_factory=set[str])
    """The casefolded names that got a finding, an error or no answer."""


def check_new(ctx: GateContext, now: datetime) -> tuple[list[GateFinding], list[str]]:
    """Registry existence and first-release age of every new package, and typosquats of every
    new direct dependency. A lookup that fails is an error, whatever the reason."""
    checked = _check(ctx, now, only=None)
    return checked.findings, [why for _, why in checked.errors] + checked.unavailable


@dataclass(frozen=True, slots=True)
class PrePrepare:
    """The lookup of the attempt's new Go modules before `go mod download` (N-1): the modules
    that failed it, or why the proxy could not be asked."""

    findings: tuple[GateFinding, ...] = ()
    unavailable: tuple[str, ...] = ()


def check_before_prepare(ctx: GateContext) -> PrePrepare:
    """Look up every new Go module before `go mod download` sends its path to the proxy, which
    fetches it from its origin (red-team v0.4, N-1; R-20). The lookups ask the proxy's cache
    only (`Disable-Module-Fetch`). A missing, too new, lookalike or invalid module, or one whose
    age the proxy cannot tell, is a finding, and so is a new version (of any module) the
    proxy has not cached; a lookup that got no answer is `unavailable`."""
    checked = _check(ctx, ctx.now, only=Ecosystem.GO)
    _check_versions(ctx, checked)
    unknown = [_finding(path, "unknown-age", why) for path, why in checked.errors]
    return PrePrepare(tuple(checked.findings + unknown)[:100], tuple(checked.unavailable))


def _check(ctx: GateContext, now: datetime, *, only: Ecosystem | None) -> _Checked:
    checked = _Checked()
    packages = [p for p in _to_check(ctx) if only is None or p[1] is only]
    if len(packages) > MAX_LOOKUPS:
        checked.errors.append((packages[0][0], f"{len(packages)} new packages, more than the "
                               f"{MAX_LOOKUPS} aipm looks up"))  # fmt: skip
        packages = packages[:MAX_LOOKUPS]
    began = _clock()
    for index, (path, eco, name, direct) in enumerate(packages):
        if _clock() - began > DEPS_BUDGET_S:
            left = len(packages) - index
            checked.unavailable.append(
                f"registry lookups took over {DEPS_BUDGET_S:.0f} s; "
                f"{left} package(s) were not checked"
            )
            break
        sizes = (len(checked.findings), len(checked.errors), len(checked.unavailable))
        _check_one(ctx, checked, (path, eco, name, direct), now)
        if sizes != (len(checked.findings), len(checked.errors), len(checked.unavailable)):
            checked.flagged.add(name.casefold())
    return checked


def _check_one(
    ctx: GateContext, checked: _Checked, package: tuple[str, Ecosystem, str, bool], now: datetime
) -> None:
    path, eco, name, direct = package
    findings = checked.findings
    min_days = ctx.cfg.security.min_dependency_age_days
    squat = typosquat_of(eco, name) if direct else None
    if squat is not None:
        near = edit_distance(normalize_name(eco, name), squat, limit=1) <= 1
        how = "is one edit from" if near else "copies, under a lookalike owner,"
        findings.append(_finding(path, "typosquat", f"{name} {how} {squat}"))
    try:
        info = first_release(eco, name, fetch=ctx.fetch)
    except PolicyViolation:
        findings.append(_finding(path, "invalid-name", f"{name!r} is not a valid package name"))
        return
    except RegistryUnavailable as exc:
        checked.unavailable.append(f"{eco.value} {name}: {exc}")
        return
    except RegistryError as exc:
        checked.errors.append((path, f"{eco.value} {name}: {exc}"))
        return
    if not info.exists:
        findings.append(_finding(path, "missing", f"{name} does not exist on {_REGISTRY[eco]}"))
    elif info.first_release is not None and not age_ok(
        info.first_release, min_days=min_days, now=now
    ):
        first = info.first_release.date().isoformat()
        message = f"{name} was first released on {first}, less than {min_days} days ago"
        findings.append(_finding(path, "too-new", message))


def _check_versions(ctx: GateContext, checked: _Checked) -> None:
    """Every (module, version) a changed `go.mod` newly requires must already be in the Go
    proxy's cache: `go mod download` would otherwise make the proxy fetch that version from its
    origin, and the version string can carry data as well as the path can (security review of
    the v0.4 decisions). Modules whose name check already failed are not asked again."""
    pairs = [(p, m, v) for p, m, v in new_go_requirements(ctx.changes)
             if m.casefold() not in checked.flagged][:MAX_LOOKUPS]  # fmt: skip
    for path, module, version in pairs:
        try:
            cached = go_version_cached(module, version, fetch=ctx.fetch)
        except PolicyViolation:
            message = f"{module} {version[:80]!r} is not a valid module and version"
            checked.findings.append(_finding(path, "invalid-version", message))
            continue
        except RegistryUnavailable as exc:
            checked.unavailable.append(f"go {module} {version[:80]}: {exc}")
            continue
        except RegistryError as exc:
            checked.errors.append((path, f"go {module} {version[:80]}: {exc}"))
            continue
        if not cached:
            message = (f"{module} {version} is not in the Go proxy's cache; downloading it would "
                       "make the proxy fetch it from its origin")  # fmt: skip
            checked.findings.append(_finding(path, "uncached-version", message))


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
