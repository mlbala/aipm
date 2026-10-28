"""`aipm verify`: post-change checks and gates for one task (§12.7, §13)."""

from pathlib import Path


def run(
    project: Path | None,
    *,
    task_id: str,
    commit: bool,
    base: str | None,
    gate: str | None,
    override_ac: str | None,
    reason: str | None,
    accept_risk: bool,
    accept_stale: bool,
) -> None:
    """Run the use case."""
    raise NotImplementedError("v0.2: build prompt 06")
