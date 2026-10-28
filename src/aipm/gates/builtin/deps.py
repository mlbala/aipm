"""deps: osv-scanner, registry existence and age, typosquat warning. (ARCHITECTURE §13.3, v0.2)"""

from aipm.domain.models import GateReport, Workspace


def run(ws: Workspace) -> GateReport:
    """Run the gate."""
    raise NotImplementedError("v0.2: build prompt 06")
