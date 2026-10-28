"""`aipm plan`: the task graph (ARCHITECTURE §9)."""

from pathlib import Path


def run(
    project: Path | None, *, max_tasks: int | None, accept_risk: bool, accept_stale: bool
) -> None:
    """Run the use case."""
    raise NotImplementedError("v0.1: build prompt 04")
