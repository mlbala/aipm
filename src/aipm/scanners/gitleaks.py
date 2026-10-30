"""gitleaks: secrets in the staged files, as normalized findings (ARCHITECTURE §13.3).

`gitleaks dir` scans the staged copy with aipm's packaged settings (`--config`), an empty
`.gitleaksignore` (`--gitleaks-ignore-path`), `--redact` and `--exit-code 0`; findings come only
from the JSON report, and any non-zero exit is an error. Every finding is high severity.
"""

from collections.abc import Sequence
from importlib.resources import as_file, files
from typing import Any, cast

from aipm.domain.models import Severity
from aipm.scanners.base import (
    Finding,
    ScanContext,
    ScanResult,
    ScanStatus,
    Tool,
    describe,
    failed,
    find_tool,
    line_of,
    missing,
    new_dir,
    read_report,
    run_tool,
    stage_files,
    text,
)

TOOL = Tool(
    "gitleaks",
    "install gitleaks 8.30 or later (https://github.com/gitleaks/gitleaks#installing)",
)


def parse(report: object) -> list[Finding] | None:
    """Findings from a gitleaks JSON report; `None` if it is not one."""
    if not isinstance(report, list):
        return None
    found: list[Finding] = []
    for item in cast("list[object]", report):
        if isinstance(item, dict):
            entry = cast("dict[str, Any]", item)
            found.append(
                Finding(
                    tool=TOOL.name,
                    rule=text(entry.get("RuleID"), 120) or "secret",
                    severity=Severity.HIGH,
                    path=text(entry.get("File"), 512),
                    line=line_of(entry.get("StartLine")),
                    message=text(entry.get("Description")) or "possible secret",
                )
            )
    return found


def scan(ctx: ScanContext, paths: Sequence[str]) -> ScanResult:
    """Scan `paths` of the repository for secrets."""
    executable = find_tool(TOOL, ctx.repo)
    if executable is None:
        return missing(TOOL)
    work = new_dir(ctx, "gitleaks")
    stage = stage_files(ctx.repo, paths, work / "stage")
    if stage.too_large:
        return failed(TOOL, f"files too large to scan: {', '.join(stage.too_large[:5])}")
    ignore = work / "empty.gitleaksignore"
    ignore.write_bytes(b"")
    report = work / "gitleaks.json"
    with as_file(files("aipm.scanners") / "data" / "gitleaks.toml") as config:
        args = ["dir", str(stage.root), "--no-banner", "--redact", "--exit-code", "0",
                "--report-format", "json", "--report-path", str(report), "--config", str(config),
                "--gitleaks-ignore-path", str(ignore), "--log-level", "error"]  # fmt: skip
        result = run_tool(TOOL, executable, args, ctx, cwd=stage.root, out_dir=work)
    output = describe(result, ctx.redactor)
    if result.timed_out or result.returncode != 0:
        return failed(TOOL, f"gitleaks exited {result.returncode}", output)
    findings = parse(read_report(report))
    if findings is None:
        return failed(TOOL, "gitleaks wrote no report aipm can read", output)
    return ScanResult(TOOL.name, ScanStatus.OK, tuple(findings[:500]), output=output)
