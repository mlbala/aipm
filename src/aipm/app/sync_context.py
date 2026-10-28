"""`aipm sync-context`: write AGENTS.md and CLAUDE.md managed blocks."""

from collections.abc import Sequence
from pathlib import Path


def run(project: Path | None, *, tools: Sequence[str], check: bool) -> None:
    """Run the use case."""
    raise NotImplementedError("v0.1: build prompt 05")
