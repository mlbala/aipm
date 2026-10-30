"""Scanner wrappers normalize findings to `{tool, rule, severity, path, line, message}`.

Every scanner runs on a **staged copy**: the files to scan, copied as regular files (never
through a link, each capped) into a directory in the attempt's private temp dir. Scanner
configuration the repository could plant (`.gitleaks.toml`, `.gitleaksignore`, `.semgrepignore`,
`osv-scanner.toml`, `.trivyignore`) is never copied, and the argv names aipm's own settings, so
a repository cannot mute a scanner. Each scanner runs through `run_safe` with an argv fixed in
code, a constructed environment with its own `HOME` and `TMPDIR`, a timeout, and, when a sandbox
is available, the scanner profile with its rule registry as the only network (SECURITY.md §9.1).

A scanner that is not installed gives `skipped` with an install hint; a scanner that fails, or
writes a report aipm cannot read, gives `error`. Neither ever passes. Findings are T2.
"""

import json
import os
import shutil
import stat
from collections.abc import Iterable, Sequence
from dataclasses import dataclass, field
from enum import StrEnum
from pathlib import Path
from typing import Any

from aipm.domain.errors import PolicyViolation
from aipm.domain.models import Severity
from aipm.execution.process import ProcessResult, build_env, is_inside, run_safe
from aipm.execution.sandbox import ProcessKind, ProfilePaths, Runtime, profile_for
from aipm.security.network import NetworkPolicy, parse_network
from aipm.security.redact import Redactor

SCAN_TIMEOUT_S = 600.0
MAX_FILE_BYTES = 2 * 1_048_576
MAX_STAGE_BYTES = 256 * 1_048_576
MAX_STAGE_FILES = 20_000
MAX_REPORT_BYTES = 32 * 1_048_576
MAX_FINDINGS = 500
SCANNER_CONFIG_NAMES = frozenset(
    {".gitleaks.toml", ".gitleaksignore", ".semgrepignore", ".semgrep.yml", ".semgrep.yaml",
     ".semgrep", "osv-scanner.toml", ".trivyignore", "trivy.yaml", ".trivyignore.yaml"}
)  # fmt: skip
"""Files a scanner reads from the directory it scans; never staged."""

SEVERITY_ORDER = (Severity.LOW, Severity.MEDIUM, Severity.HIGH, Severity.CRITICAL)


class ScanStatus(StrEnum):
    """How one scanner run ended."""

    OK = "ok"
    SKIPPED = "skipped"
    ERROR = "error"


@dataclass(frozen=True, slots=True)
class Finding:
    """One normalized scanner finding. Everything but `tool` and `severity` is T2."""

    tool: str
    rule: str
    severity: Severity
    path: str
    line: int | None
    message: str

    def as_dict(self) -> dict[str, object]:
        """The finding as JSON-ready data."""
        return {
            "tool": self.tool,
            "rule": self.rule,
            "severity": self.severity.value,
            "path": self.path,
            "line": self.line,
            "message": self.message,
        }


@dataclass(frozen=True, slots=True)
class ScanResult:
    """A scanner's findings, or why there are none."""

    tool: str
    status: ScanStatus
    findings: tuple[Finding, ...] = ()
    reason: str = ""
    output: str = ""

    def at_least(self, level: Severity) -> list[Finding]:
        """The findings at `level` or above."""
        floor = SEVERITY_ORDER.index(level)
        return [f for f in self.findings if SEVERITY_ORDER.index(f.severity) >= floor]


@dataclass(frozen=True, slots=True)
class ScanContext:
    """Where a scanner runs: the repository (to refuse tools inside it), the attempt's private
    temp dir, the sandbox runtime if there is one, and the redactor for its output."""

    repo: Path
    temp_dir: Path
    runtime: Runtime | None = None
    redactor: Redactor = field(default_factory=lambda: Redactor({}))


@dataclass(frozen=True, slots=True)
class Tool:
    """A scanner program: its name, how to install it, and the domains it may reach."""

    name: str
    install: str
    network: str = "none"


def find_tool(tool: Tool, repo: Path) -> str | None:
    """The scanner's absolute path on PATH, `None` if missing; exit 6 if it is in the repo."""
    found = shutil.which(tool.name)
    if found is None:
        return None
    if is_inside(found, repo):
        raise PolicyViolation(
            f"the {tool.name} found on PATH ({found}) is inside the repository",
            hint="Remove relative or repository entries from PATH.",
        )
    return found


def missing(tool: Tool) -> ScanResult:
    """The result for a scanner that is not installed."""
    return ScanResult(
        tool.name, ScanStatus.SKIPPED, reason=f"{tool.name} is not installed: {tool.install}"
    )


def failed(tool: Tool, reason: str, output: str = "") -> ScanResult:
    """The result for a scanner that did not finish or wrote nothing aipm can read."""
    return ScanResult(tool.name, ScanStatus.ERROR, reason=reason[:500], output=output)


@dataclass(frozen=True, slots=True)
class Stage:
    """A staged copy of files to scan, and what could not be staged."""

    root: Path
    files: tuple[str, ...]
    too_large: tuple[str, ...] = ()


def _private_dir(path: Path) -> Path:
    path.mkdir(mode=0o700, parents=True, exist_ok=False)
    return path


def stage_files(repo: Path, paths: Iterable[str], into: Path) -> Stage:
    """Copy regular files from `repo` into `into` (created, 0700), keeping their relative paths.

    Links, directories, special files and scanner configuration are skipped; a file over
    `MAX_FILE_BYTES` is listed in `too_large`. Paths come from git or `owns_files` and have
    passed `safe_relpath`-style checks; each is opened with `O_NOFOLLOW` and parents are
    re-created here, never followed.
    """
    root = _private_dir(into)
    copied: list[str] = []
    big: list[str] = []
    total = 0
    for rel in sorted(set(paths)):
        parts = rel.split("/")
        if parts[-1] in SCANNER_CONFIG_NAMES or any(p in ("", ".", "..") for p in parts):
            continue
        if len(copied) >= MAX_STAGE_FILES or total > MAX_STAGE_BYTES:
            big.append(rel)
            continue
        data = _read_regular(repo, parts)
        if data is None:
            continue
        if len(data) > MAX_FILE_BYTES:
            big.append(rel)
            continue
        target = root.joinpath(*parts)
        target.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        fd = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        with os.fdopen(fd, "wb") as handle:
            handle.write(data)
        copied.append(rel)
        total += len(data)
    return Stage(root, tuple(copied), tuple(big))


def _read_regular(repo: Path, parts: Sequence[str]) -> bytes | None:
    """A regular file's bytes (up to the cap + 1), opened without following any link."""
    current = Path(os.path.realpath(repo))
    for part in parts[:-1]:
        current = current / part
        try:
            info = os.lstat(current)
        except OSError:
            return None
        if not stat.S_ISDIR(info.st_mode):
            return None
    try:
        fd = os.open(current / parts[-1], os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    except OSError:
        return None
    if not stat.S_ISREG(os.fstat(fd).st_mode):
        os.close(fd)
        return None
    with os.fdopen(fd, "rb") as handle:
        return handle.read(MAX_FILE_BYTES + 1)


def run_tool(
    tool: Tool,
    executable: str,
    args: Sequence[str],
    ctx: ScanContext,
    *,
    cwd: Path,
    out_dir: Path,
) -> ProcessResult:
    """Run a scanner with its own `HOME` and `TMPDIR` under `out_dir`, sandboxed if possible."""
    home = out_dir / "home"
    tmp = out_dir / "tmp"
    for path in (home, tmp):
        path.mkdir(mode=0o700, parents=True, exist_ok=True)
    env = build_env(extra={"HOME": str(home), "TMPDIR": str(tmp), "XDG_CACHE_HOME": str(tmp)})
    profile = None
    if ctx.runtime is not None:
        network: NetworkPolicy = parse_network(tool.network)
        paths = ProfilePaths(workspace=cwd, temp_dir=out_dir, home=Path.home(), output_dir=out_dir)
        profile = profile_for(ProcessKind.SCANNER, network, paths, runtime=ctx.runtime)
    return run_safe(
        [executable, *args],
        cwd=cwd,
        env=env,
        timeout_s=SCAN_TIMEOUT_S,
        max_output_bytes=1_048_576,
        sandbox=profile,
    )


def describe(result: ProcessResult, redactor: Redactor) -> str:
    """A scanner's console output for the run dir: decoded, redacted, cut to its tail."""
    text = (result.stdout + b"\n" + result.stderr).decode("utf-8", errors="replace")
    return redactor.redact(text[-65_536:])


def read_report(path: Path) -> Any:
    """A scanner's JSON report (T2), or `None` if missing, oversized or not JSON."""
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    except OSError:
        return None
    if not stat.S_ISREG(os.fstat(fd).st_mode):
        os.close(fd)
        return None
    with os.fdopen(fd, "rb") as handle:
        data = handle.read(MAX_REPORT_BYTES + 1)
    if len(data) > MAX_REPORT_BYTES:
        return None
    try:
        return json.loads(data or b"null")
    except (ValueError, RecursionError):
        return None


def severity_of(value: object, *, default: Severity = Severity.HIGH) -> Severity:
    """Map a scanner's severity word or CVSS score to aipm's; unknown counts as `default`."""
    if isinstance(value, (int, float)) and not isinstance(value, bool):
        return _from_score(float(value))
    if not isinstance(value, str):
        return default
    word = value.strip().casefold()
    words = {
        "critical": Severity.CRITICAL,
        "high": Severity.HIGH,
        "error": Severity.HIGH,
        "medium": Severity.MEDIUM,
        "moderate": Severity.MEDIUM,
        "warning": Severity.MEDIUM,
        "low": Severity.LOW,
        "info": Severity.LOW,
        "note": Severity.LOW,
    }
    if word in words:
        return words[word]
    try:
        return _from_score(float(word))
    except ValueError:
        return default


def _from_score(score: float) -> Severity:
    if score >= 9.0:
        return Severity.CRITICAL
    if score >= 7.0:
        return Severity.HIGH
    if score >= 4.0:
        return Severity.MEDIUM
    return Severity.LOW


def text(value: object, limit: int = 300) -> str:
    """A report field as a short string (T2)."""
    return value[:limit] if isinstance(value, str) else ""


def line_of(value: object) -> int | None:
    """A report field as a line number."""
    return value if isinstance(value, int) and not isinstance(value, bool) and value > 0 else None


def new_dir(ctx: ScanContext, name: str) -> Path:
    """A fresh private directory for one scanner run in the attempt's temp dir."""
    base = ctx.temp_dir / name
    index = 0
    while base.exists():
        index += 1
        base = ctx.temp_dir / f"{name}-{index}"
    return _private_dir(base)
