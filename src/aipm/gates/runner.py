"""The gate runner (C-15, ARCHITECTURE §13.2)."""

from typing import Protocol

from aipm.domain.models import GateReport, Task, Workspace


class GateRunner(Protocol):
    """Run the prepare step and every gate for one task attempt."""

    def run(self, task: Task, ws: Workspace, base_sha: str) -> GateReport:
        """Return the gate report; only deterministic gates decide done."""
        ...
