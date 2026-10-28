"""`aipm task`: manual task state control; every change is recorded."""

from pathlib import Path


def run(project: Path | None, *, action: str, task_id: str, reason: str | None) -> None:
    """Run the use case."""
    raise NotImplementedError("v0.2: build prompt 06")
