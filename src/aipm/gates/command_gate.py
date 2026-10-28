"""Command gates: compile_gate, then sandbox.wrap, then run_safe with no network (§13.2)."""

from aipm.domain.models import GateDef, GateReport, Workspace


def run_command_gate(gate: GateDef, ws: Workspace) -> GateReport:
    """Run one command gate."""
    raise NotImplementedError("v0.2: build prompt 06")
