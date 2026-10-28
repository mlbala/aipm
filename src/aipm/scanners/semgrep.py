"""Wrapper for semgrep: JSON output normalized to findings (ARCHITECTURE §13.3)."""

from pathlib import Path

from aipm.scanners.base import Finding


def scan(repo: Path) -> list[Finding]:
    """Run semgrep and normalize its findings."""
    raise NotImplementedError("v0.2: build prompt 06")
