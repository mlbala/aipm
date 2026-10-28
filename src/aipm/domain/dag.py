"""Plan validation: acyclicity, ownership overlap, gate-menu checks, size caps (C-8, §9)."""

from collections.abc import Sequence

from aipm.domain.models import Task


def validate_plan(tasks: Sequence[Task]) -> list[str]:
    """Return every validation problem in the task graph; an empty list means valid."""
    raise NotImplementedError("v0.1: build prompt 04")
