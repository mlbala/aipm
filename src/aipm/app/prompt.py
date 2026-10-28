"""`aipm prompt`: the compiled task prompt; needs trust (SECURITY.md §6 rule 3)."""

from pathlib import Path


def run(
    project: Path | None,
    *,
    task_id: str,
    tool: str | None,
    copy: bool,
    out: Path | None,
    fix: bool,
    accept_stale: bool,
) -> None:
    """Run the use case."""
    raise NotImplementedError("v0.1: build prompt 05")
