"""Golden snapshots (build prompt 08): the go and rust-cargo stack templates, as every argv they
would run once compiled through the command policy, and their gate menus.

A change here changes what users trust (`aipm trust --show`): update the snapshots only when the
template change is intended, and say so in the commit message (AGENTS.md).
"""

from pathlib import Path

import pytest
from syrupy.assertion import SnapshotAssertion

from aipm.config.schema import Config
from aipm.config.stacks import load_stack
from aipm.security.command_policy import compile_gate, compile_prepare
from aipm.security.paths import SafeRelPath

PATHS = {
    "go": [SafeRelPath("internal/booking/slots.go"), SafeRelPath("internal/booking/slots_test.go")],
    "rust-cargo": [SafeRelPath("src/booking.rs"), SafeRelPath("tests/booking.rs")],
}


def compiled(name: str) -> dict[str, object]:
    stack = load_stack(name)
    policy = Config.model_validate(stack.model_dump(mode="json")).command_policy()
    assert stack.prepare is not None
    gates: dict[str, object] = {}
    for gate_name, gate in sorted(stack.gates.items()):
        if gate.run is None:
            gates[gate_name] = f"builtin {gate.builtin}"
        else:
            report = Path("/attempt/report.xml")
            gates[gate_name] = list(
                compile_gate(gate, paths=PATHS[name], policy=policy, report_file=report)
            )
    return {
        "allowed_executables": [list(p) for p in stack.allowed_executables],
        "test_roots": list(stack.test_roots),
        "prepare": list(compile_prepare(stack.prepare, policy=policy)),
        "gates": gates,
        "required": sorted(n for n, g in stack.gates.items() if g.required),
    }


@pytest.mark.parametrize("name", sorted(PATHS))
def test_stack_template(name: str, snapshot: SnapshotAssertion) -> None:
    assert compiled(name) == snapshot
