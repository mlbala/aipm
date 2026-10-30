"""semgrep: static analysis with pinned rule packs (ARCHITECTURE §13.3).

Runs `semgrep scan --json --metrics off --disable-version-check --disable-nosem` with each pack
in `scanners.semgrep.configs` (never `--config auto`) on the staged copy. Rule packs come from
`semgrep.dev`, the only domain the sandbox lets it reach. `nosemgrep` comments in the scanned
code are ignored, so the code under review cannot silence a rule.
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
    "semgrep",
    "install semgrep 1.183 or later (`uv tool install semgrep` or `brew install semgrep`)",
    network="api-only:semgrep.dev",
)


def parse(report: object, root: str) -> list[Finding] | None:
    """Findings from a semgrep JSON report; `None` if it is not one."""
    if not isinstance(report, dict):
        return None
    results = cast("dict[str, Any]", report).get("results")
    if not isinstance(results, list):
        return None
    found: list[Finding] = []
    for item in cast("list[object]", results):
        if not isinstance(item, dict):
            continue
        entry = cast("dict[str, Any]", item)
        extra = entry.get("extra")
        extra = cast("dict[str, Any]", extra) if isinstance(extra, dict) else {}
        start = entry.get("start")
        start = cast("dict[str, Any]", start) if isinstance(start, dict) else {}
        path = text(entry.get("path"), 1024).removeprefix(root).lstrip("/")
        found.append(
            Finding(
                tool=TOOL.name,
                rule=text(entry.get("check_id"), 200) or "rule",
                severity=severity_of(extra.get("severity")),
                path=path[:512],
                line=line_of(start.get("line")),
                message=text(extra.get("message")),
            )
        )
    return found


def scan(ctx: ScanContext, paths: Sequence[str], *, configs: Sequence[str]) -> ScanResult:
    """Run the pinned rule packs over `paths`."""
    executable = find_tool(TOOL, ctx.repo)
    if executable is None:
        return missing(TOOL)
    if not configs or any(c == "auto" or not c.startswith(("p/", "r/")) for c in configs):
        return failed(TOOL, "scanners.semgrep.configs must name pinned p/ or r/ rule packs")
    work = new_dir(ctx, "semgrep")
    stage = stage_files(ctx.repo, paths, work / "stage")
    if not stage.files:
        return ScanResult(TOOL.name, ScanStatus.OK, reason="no files to scan")
    report = work / "semgrep.json"
    args = ["scan", "--json", "--output", str(report), "--metrics", "off",
            "--disable-version-check", "--disable-nosem", "--quiet"]  # fmt: skip
    for config in configs:
        args += ["--config", config]
    args.append(str(stage.root))
    result = run_tool(TOOL, executable, args, ctx, cwd=stage.root, out_dir=work)
    output = describe(result, ctx.redactor)
    if result.timed_out or result.returncode not in (0, 1):
        return failed(TOOL, f"semgrep exited {result.returncode}", output)
    findings = parse(read_report(report), str(stage.root))
    if findings is None:
        return failed(TOOL, "semgrep wrote no report aipm can read", output)
    return ScanResult(TOOL.name, ScanStatus.OK, tuple(findings[:500]), output=output)
