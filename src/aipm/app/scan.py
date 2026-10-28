"""`aipm scan`: every scanner over the whole repository."""

from pathlib import Path


def run(project: Path | None, *, scanner: str | None, fail_on: str | None) -> None:
    """Run the use case."""
    raise NotImplementedError("v0.2: build prompt 06")
