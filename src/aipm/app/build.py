"""`aipm build`: every ready task, in parallel where safe (§12)."""

from pathlib import Path


def run(
    project: Path | None,
    *,
    tool: str | None,
    parallel: int | None,
    max_retries: int | None,
    budget: float | None,
    timeout: str | None,
    only: str | None,
    dry_run: bool,
    accept_stale: bool,
) -> None:
    """Run the use case."""
    raise NotImplementedError("v0.3: build prompt 07")
