"""ac_review: the LLM AC reviewer, veto only (ADR-0007). (ARCHITECTURE §13.3, v0.2)"""

from aipm.domain.models import GateReport, Workspace


def run(ws: Workspace) -> GateReport:
    """Run the gate."""
    raise NotImplementedError("v0.2: build prompt 06")
