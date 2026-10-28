"""`aipm auto`: loop next_command until built; never records trust (§7.3)."""

from pathlib import Path


def run(
    project: Path | None,
    *,
    yes: bool,
    accept_risk: bool,
    accept_stale: bool,
    tool: str | None,
    parallel: int | None,
    max_retries: int | None,
    budget: float | None,
    timeout: str | None,
    only: str | None,
    dry_run: bool,
) -> None:
    """Run the use case."""
    raise NotImplementedError("v0.4: build prompt 08")
