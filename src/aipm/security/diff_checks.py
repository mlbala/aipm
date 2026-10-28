"""Post-change checks (C-16, ARCHITECTURE §12.4 step 3): a pure function over a ChangeSet."""

from dataclasses import dataclass

from aipm.domain.models import ChangeSet, Task


@dataclass(frozen=True, slots=True)
class Violation:
    """One post-change finding, `minor` or `severe` (placeholder, prompt 06)."""


def check_changes(changes: ChangeSet, task: Task) -> list[Violation]:
    """Check scope, protected paths, test tampering, dependencies and git integrity."""
    raise NotImplementedError("v0.2: build prompt 06")
