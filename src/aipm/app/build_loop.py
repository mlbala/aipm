"""The asyncio build orchestrator (C-18, ARCHITECTURE §12.4, v0.3)."""

from collections.abc import Sequence

from aipm.domain.models import Task


async def run_build(tasks: Sequence[Task], *, parallel: int) -> None:
    """Schedule, dispatch, check, gate and commit every ready task."""
    raise NotImplementedError("v0.3: build prompt 07")
