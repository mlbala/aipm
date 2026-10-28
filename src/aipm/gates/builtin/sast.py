"""sast: semgrep with pinned rule packs and --metrics off (ARCHITECTURE §13.3, v0.2).

`--config auto` is never used.
"""

from aipm.domain.models import GateReport, Workspace


def run(ws: Workspace) -> GateReport:
    """Run the gate."""
    raise NotImplementedError("v0.2: build prompt 06")
