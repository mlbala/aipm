"""`aipm init`: create `.pm/`, detect the stack, write the repo map, run trust."""

from pathlib import Path


def run(
    project: Path | None, *, provider: str | None, tool: str | None, stack: str | None, force: bool
) -> None:
    """Run the use case."""
    raise NotImplementedError("v0.1: build prompt 02")
