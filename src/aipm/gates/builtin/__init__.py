"""Built-in gates (ARCHITECTURE §13.3) and what they share.

Each returns a `BuiltinOutcome`: the gate result, and whether a scanner it needed was missing.
A required gate whose scanner is missing is an `error` with an install hint (exit 8 from
`verify`), never a pass; an optional one is `skipped`.
"""

import time
from collections.abc import Iterable
from dataclasses import dataclass

from aipm.domain.models import GateFinding, GateResult, GateStatus
from aipm.scanners.base import Finding

MAX_FINDINGS = 100


@dataclass(frozen=True, slots=True)
class BuiltinOutcome:
    """A built-in gate's result, and whether its scanner was missing."""

    result: GateResult
    missing_tool: bool = False
    full_output: str = ""


def to_findings(found: Iterable[Finding]) -> list[GateFinding]:
    """Scanner findings as report entries (capped)."""
    out: list[GateFinding] = []
    for f in found:
        if len(out) >= MAX_FINDINGS:
            break
        out.append(
            GateFinding(
                tool=f.tool[:40], rule=f.rule[:200], severity=f.severity, path=f.path[:512],
                line=f.line if f.line is None or f.line <= 10_000_000 else None,
                message=f.message[:500],
            )
        )  # fmt: skip
    return out


def outcome(
    name: str,
    status: GateStatus,
    summary: str,
    *,
    required: bool,
    started: float,
    findings: Iterable[GateFinding] = (),
    missing_tool: bool = False,
    output: str = "",
) -> BuiltinOutcome:
    """Build a built-in gate's outcome."""
    result = GateResult(
        name=name,
        status=status,
        required=required,
        duration_ms=int((time.monotonic() - started) * 1000),
        summary=summary[:1000],
        findings=list(findings)[:MAX_FINDINGS],
        output=output[:65_536],
    )
    return BuiltinOutcome(result, missing_tool, output)


def tool_missing(name: str, reason: str, *, required: bool, started: float) -> BuiltinOutcome:
    """A scanner is not installed: an error (and exit 8) when the gate is required."""
    if required:
        return outcome(name, GateStatus.ERROR, f"required, but {reason}", required=True,
                       started=started, missing_tool=True)  # fmt: skip
    return outcome(name, GateStatus.SKIPPED, reason, required=False, started=started)
