"""Pure scheduler: ready set, disjoint-ownership batching, serialized resources (§12.3)."""

from collections.abc import Sequence

from aipm.domain.models import Task


def next_batch(tasks: Sequence[Task], *, parallel: int) -> list[Task]:
    """Return the next tasks that may run together, in a deterministic order."""
    raise NotImplementedError("v0.3: build prompt 07")
