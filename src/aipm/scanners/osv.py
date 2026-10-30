"""osv-scanner: known vulnerabilities in the staged lockfiles (ARCHITECTURE §13.3).

`osv-scanner scan source --format json -L <lockfile>…` with an empty `--config`, so a planted
`osv-scanner.toml` cannot ignore an advisory. Exit 0 is clean, 1 means vulnerabilities, 128 means
no packages were found; anything else is an error. A vulnerability's severity is its group's
highest CVSS score, else the advisory's own word; unknown counts as high.
"""

from collections.abc import Sequence
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
    missing,
    new_dir,
    read_report,
    run_tool,
    severity_of,
    stage_files,
    text,
)

TOOL = Tool(
    "osv-scanner",
    "install osv-scanner 2.7 or later (https://google.github.io/osv-scanner/installation/)",
    network="api-only:api.osv.dev,api.deps.dev",
)


def _dict(value: object) -> dict[str, Any]:
    return cast("dict[str, Any]", value) if isinstance(value, dict) else {}


def _list(value: object) -> list[object]:
    return cast("list[object]", value) if isinstance(value, list) else []


def _severity(package: dict[str, Any], vuln: dict[str, Any]) -> Severity:
    vid = vuln.get("id")
    for group in _list(package.get("groups")):
        g = _dict(group)
        if vid in _list(g.get("ids")) and g.get("max_severity") not in (None, ""):
            return severity_of(g.get("max_severity"))
    return severity_of(_dict(vuln.get("database_specific")).get("severity"))


def parse(report: object, root: str) -> list[Finding] | None:
    """Findings from an osv-scanner JSON report; `None` if it is not one."""
    if not isinstance(report, dict):
        return None
    results = cast("dict[str, Any]", report).get("results", [])
    if not isinstance(results, list):
        return None
    found: list[Finding] = []
    for result in cast("list[object]", results):
        source = text(_dict(_dict(result).get("source")).get("path"), 1024)
        for package in map(_dict, _list(_dict(result).get("packages"))):
            info = _dict(package.get("package"))
            name = f"{text(info.get('name'), 120)}@{text(info.get('version'), 60)}"
            for vuln in map(_dict, _list(package.get("vulnerabilities"))):
                found.append(
                    Finding(
                        tool=TOOL.name,
                        rule=text(vuln.get("id"), 80) or "advisory",
                        severity=_severity(package, vuln),
                        path=source.removeprefix(root).lstrip("/")[:512],
                        line=None,
                        message=f"{name}: {text(vuln.get('summary'), 240)}",
                    )
                )
    return found


def scan(ctx: ScanContext, lockfiles: Sequence[str]) -> ScanResult:
    """Look the packages of `lockfiles` up in OSV."""
    executable = find_tool(TOOL, ctx.repo)
    if executable is None:
        return missing(TOOL)
    work = new_dir(ctx, "osv")
    stage = stage_files(ctx.repo, lockfiles, work / "stage")
    if not stage.files:
        return ScanResult(TOOL.name, ScanStatus.OK, reason="no lockfiles to scan")
    config = work / "osv-scanner.toml"
    config.write_bytes(b"")
    report = work / "osv.json"
    args = ["scan", "source", "--format", "json", "--output", str(report), "--config", str(config)]
    for rel in stage.files:
        args += ["-L", str(stage.root / rel)]
    result = run_tool(TOOL, executable, args, ctx, cwd=stage.root, out_dir=work)
    output = describe(result, ctx.redactor)
    if result.timed_out or result.returncode not in (0, 1, 128):
        return failed(TOOL, f"osv-scanner exited {result.returncode}", output)
    if result.returncode == 128:
        return ScanResult(TOOL.name, ScanStatus.OK, reason="no packages found", output=output)
    findings = parse(read_report(report), str(stage.root))
    if findings is None:
        return failed(TOOL, "osv-scanner wrote no report aipm can read", output)
    return ScanResult(TOOL.name, ScanStatus.OK, tuple(findings[:500]), output=output)
