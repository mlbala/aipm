"""`aipm scan`: every scanner over the whole repository (ARCHITECTURE §16).

gitleaks, semgrep (the pinned packs), osv-scanner (the lockfiles) and trivy run on a staged copy
of the tracked and untracked, not ignored, files, in the scanner sandbox when there is one.
Config-defined scanners (`scanners.extra`) are part of the execution surface: they need trust
(exit 6) and their argv passes the command policy; each runs in the repository with no network,
and a non-zero exit is a high finding. `--scanner NAME` runs one scanner and exits 8 if it is not
installed. `--fail-on` (default high) is the lowest severity that makes the scan fail (exit 3).
"""

import shutil
import tempfile
from dataclasses import dataclass, field
from pathlib import Path

from aipm.app.runtime import user_redactor
from aipm.app.trust import require_trusted
from aipm.app.workspace import find_repo_root
from aipm.config.loader import LoadedConfig, load_config
from aipm.domain.errors import MissingCapability, PolicyViolation, UsageError, VerificationFailed
from aipm.domain.models import Severity
from aipm.execution.git import repo_files
from aipm.execution.process import build_env, run_safe
from aipm.execution.sandbox import ProcessKind, ProfilePaths, profile_for, resolve_sandbox
from aipm.gates.command_gate import resolve_program
from aipm.scanners import gitleaks, osv, semgrep, trivy
from aipm.scanners.base import SCAN_TIMEOUT_S, Finding, ScanContext, ScanResult, ScanStatus
from aipm.security.command_policy import check_argv
from aipm.security.diff_checks import LOCKFILES
from aipm.security.network import NetworkPolicy, NetworkProfile
from aipm.security.paths import is_within
from aipm.security.sanitize import strip_terminal_escapes

BUILTIN = ("gitleaks", "semgrep", "osv-scanner", "trivy")


@dataclass(frozen=True, slots=True)
class ScanOptions:
    """The command's flags."""

    scanner: str | None = None
    fail_on: str | None = None


@dataclass(slots=True)
class ScanReport:
    """Every scanner's result, and whether the scan fails."""

    repo: str
    fail_on: Severity
    results: list[ScanResult] = field(default_factory=list[ScanResult])
    warnings: list[str] = field(default_factory=list[str])

    def blocking(self) -> list[Finding]:
        """The findings at `fail_on` or above."""
        return [f for r in self.results for f in r.at_least(self.fail_on)]

    def to_data(self) -> dict[str, object]:
        """The `--json` payload."""
        return {
            "repo": self.repo,
            "fail_on": self.fail_on.value,
            "failed": bool(self.blocking()),
            "scanners": [
                {
                    "tool": r.tool,
                    "status": r.status.value,
                    "reason": r.reason,
                    "findings": [f.as_dict() for f in r.findings],
                }
                for r in self.results
            ],
            "warnings": list(self.warnings),
        }


def _severity(value: str | None) -> Severity:
    if value is None:
        return Severity.HIGH
    try:
        return Severity(value.casefold())
    except ValueError:
        raise UsageError(
            f"--fail-on is one of low, medium, high, critical, not {value!r}"
        ) from None


def _extra(name: str, run: tuple[str, ...], ctx: ScanContext, loaded: LoadedConfig) -> ScanResult:
    """A config-defined scanner: checked argv, the repository as cwd, no network."""
    argv = list(check_argv(run, loaded.config.command_policy(), stage="gate"))
    argv[0] = resolve_program(argv[0], ctx.repo)
    profile = None
    if ctx.runtime is not None:
        paths = ProfilePaths(workspace=ctx.repo, temp_dir=ctx.temp_dir, home=Path.home(),
                             output_dir=ctx.temp_dir)  # fmt: skip
        network = NetworkPolicy(NetworkProfile.NONE)
        profile = profile_for(ProcessKind.SCANNER, network, paths, runtime=ctx.runtime)
    result = run_safe(argv, cwd=ctx.repo, env=build_env(extra={"TMPDIR": str(ctx.temp_dir)}),
                      timeout_s=SCAN_TIMEOUT_S, sandbox=profile)  # fmt: skip
    output = ctx.redactor.redact((result.stdout + result.stderr).decode("utf-8", "replace"))
    if result.timed_out:
        return ScanResult(name, ScanStatus.ERROR, reason="timed out", output=output[-65_536:])
    if result.returncode == 0:
        return ScanResult(name, ScanStatus.OK, output=output[-65_536:])
    last = next((strip_terminal_escapes(x).strip() for x in reversed(output.splitlines())
                 if x.strip()), "")  # fmt: skip
    finding = Finding(name, "exit", Severity.HIGH, "", None,
                      f"exit {result.returncode}: {last[:200]}")  # fmt: skip
    return ScanResult(name, ScanStatus.OK, (finding,), output=output[-65_536:])


def _files(root: Path) -> list[str]:
    names = repo_files(root)
    if any(n is None for n in names):
        raise UsageError("git lists a file whose name aipm cannot read; rename or remove it")
    return [n for n in names if n is not None and not n.startswith(".pm/")]


def _builtin(name: str, ctx: ScanContext, files: list[str], loaded: LoadedConfig) -> ScanResult:
    if name == "gitleaks":
        return gitleaks.scan(ctx, files)
    if name == "semgrep":
        return semgrep.scan(ctx, files, configs=loaded.config.scanners.semgrep.configs)
    if name == "osv-scanner":
        locks = [f for f in files if f.rsplit("/", 1)[-1] in LOCKFILES]
        return osv.scan(ctx, locks)
    return trivy.scan(ctx, files)


def run(project: Path | None, options: ScanOptions) -> ScanReport:
    """Run the use case."""
    root = find_repo_root(project)
    loaded = load_config(root)
    extras = dict(loaded.config.scanners.extra)
    known = [*BUILTIN, *sorted(extras)]
    if options.scanner is not None and options.scanner not in known:
        raise UsageError(
            f"there is no scanner {options.scanner!r}", hint=f"Scanners: {', '.join(known)}"
        )
    names = [options.scanner] if options.scanner else known
    fail_on = _severity(options.fail_on)
    if any(n in extras for n in names):
        require_trusted(root, loaded, command="scan")
    temp = Path(tempfile.mkdtemp(prefix="aipm-scan-"))
    try:
        if is_within(temp, root):
            raise PolicyViolation("the temporary directory is inside the repository",
                                  hint="Check TMPDIR.")  # fmt: skip
        sandbox = resolve_sandbox(mode=loaded.config.dispatch.sandbox.value,
                                  require=loaded.config.security.require_sandbox, repo=root,
                                  temp_dir=temp, what="scanners")  # fmt: skip
        report = ScanReport(str(root), fail_on, warnings=list(loaded.warnings))
        if sandbox.warning:
            report.warnings.append(sandbox.warning)
        ctx = ScanContext(repo=root, temp_dir=temp, runtime=sandbox.runtime,
                          redactor=user_redactor(root))  # fmt: skip
        files = _files(root)
        for name in names:
            if name in extras:
                report.results.append(_extra(name, extras[name].run, ctx, loaded))
            else:
                report.results.append(_builtin(name, ctx, files, loaded))
    finally:
        shutil.rmtree(temp, ignore_errors=True)
    return report


def check(report: ScanReport, options: ScanOptions) -> None:
    """Raise the exit code a finished scan ends with: 8 for a named scanner that is missing,
    3 when a finding reaches `--fail-on`."""
    if options.scanner is not None and report.results[0].status is ScanStatus.SKIPPED:
        raise MissingCapability(report.results[0].reason, data=report.to_data())
    errors = [r for r in report.results if r.status is ScanStatus.ERROR]
    blocking = report.blocking()
    if blocking or errors:
        what = f"{len(blocking)} finding(s) at {report.fail_on.value} or above"
        if errors:
            what += f", {len(errors)} scanner error(s)"
        raise VerificationFailed(f"the scan failed: {what}", data=report.to_data())
