"""Scanner wrappers normalize findings to {tool, rule, severity, path, line, message}."""

from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True, slots=True)
class Finding:
    """One normalized scanner finding (placeholder, prompt 06)."""


def run_scanner(name: str, repo: Path) -> list[Finding]:
    """Run a scanner; a missing scanner is `skipped` with a reason."""
    raise NotImplementedError("v0.2: build prompt 06")
