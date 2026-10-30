"""trivy: vulnerabilities, secrets and misconfiguration over the staged repository (`aipm scan`).

`trivy fs --format json --scanners vuln,secret,misconfig --quiet` with its cache in the scanner's
own directory and `--skip-version-check`. Its vulnerability database comes from the registries
the sandbox lets it reach.
"""

from collections.abc import Sequence
from typing import Any, cast

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
    severity_of,
    stage_files,
    text,
)

TOOL = Tool(
    "trivy",
    "install trivy 0.76 or later (https://trivy.dev/latest/getting-started/installation/)",
    network="api-only:mirror.gcr.io,ghcr.io,pkg-containers.githubusercontent.com",
)
_KINDS = (
    ("Vulnerabilities", "VulnerabilityID", "PkgName"),
    ("Secrets", "RuleID", "Title"),
    ("Misconfigurations", "ID", "Title"),
)


def _dict(value: object) -> dict[str, Any]:
    return cast("dict[str, Any]", value) if isinstance(value, dict) else {}


def _list(value: object) -> list[object]:
    return cast("list[object]", value) if isinstance(value, list) else []


def parse(report: object) -> list[Finding] | None:
    """Findings from a trivy JSON report; `None` if it is not one."""
    if not isinstance(report, dict):
        return None
    found: list[Finding] = []
    for result in map(_dict, _list(cast("dict[str, Any]", report).get("Results"))):
        target = text(result.get("Target"), 512)
        for key, rule_key, title_key in _KINDS:
            for item in map(_dict, _list(result.get(key))):
                line = item.get("StartLine") or _dict(item.get("CauseMetadata")).get("StartLine")
                found.append(
                    Finding(
                        tool=TOOL.name,
                        rule=text(item.get(rule_key), 120) or key.lower(),
                        severity=severity_of(item.get("Severity")),
                        path=target,
                        line=line_of(line),
                        message=text(item.get(title_key)) or text(item.get("Title")),
                    )
                )
    return found


def scan(ctx: ScanContext, paths: Sequence[str]) -> ScanResult:
    """Scan `paths` of the repository."""
    executable = find_tool(TOOL, ctx.repo)
    if executable is None:
        return missing(TOOL)
    work = new_dir(ctx, "trivy")
    stage = stage_files(ctx.repo, paths, work / "stage")
    report = work / "trivy.json"
    args = ["fs", "--format", "json", "--output", str(report), "--scanners",
            "vuln,secret,misconfig", "--quiet", "--skip-version-check", "--cache-dir",
            str(work / "cache"), str(stage.root)]  # fmt: skip
    result = run_tool(TOOL, executable, args, ctx, cwd=stage.root, out_dir=work)
    output = describe(result, ctx.redactor)
    if result.timed_out or result.returncode != 0:
        return failed(TOOL, f"trivy exited {result.returncode}", output)
    findings = parse(read_report(report))
    if findings is None:
        return failed(TOOL, "trivy wrote no report aipm can read", output)
    return ScanResult(TOOL.name, ScanStatus.OK, tuple(findings[:500]), output=output)
