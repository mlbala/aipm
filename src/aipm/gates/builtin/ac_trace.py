"""ac_trace: every AC ID appears in tests that ran (ARCHITECTURE §13.3, v0.2).

The test report is read only from the aipm-generated `{report_file}` path.
"""

from aipm.domain.models import GateReport, Workspace


def run(ws: Workspace) -> GateReport:
    """Run the gate."""
    raise NotImplementedError("v0.2: build prompt 06")
