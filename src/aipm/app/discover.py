"""`aipm discover`: the requirements interview (ARCHITECTURE §8)."""

from pathlib import Path


def run(
    project: Path | None,
    *,
    from_file: Path | None,
    answers: Path | None,
    defaults: bool,
    edit: str | None,
    max_rounds: int | None,
    threshold: float | None,
    accept_risk: bool,
) -> None:
    """Run the use case."""
    raise NotImplementedError("v0.1: build prompt 03")
