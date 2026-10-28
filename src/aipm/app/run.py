"""`aipm run`: one attempt loop for one task (§12.4)."""

from pathlib import Path


def run(
    project: Path | None,
    *,
    task_id: str,
    tool: str | None,
    timeout: str | None,
    budget: float | None,
    dry_run: bool,
    accept_stale: bool,
) -> None:
    """Run the use case."""
    raise NotImplementedError("v0.3: build prompt 07")
