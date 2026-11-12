"""Gates in a build (ARCHITECTURE §13.2): fail-fast, and the agent's config home kept from them."""

import dataclasses
import sys
from pathlib import Path

import pytest

from aipm.domain.models import GateStatus, NetworkProfile, PrepareDef
from aipm.execution.sandbox import ProcessKind
from aipm.gates.command_gate import sandbox_for
from aipm.gates.runner import run_gates
from tests.security.test_gates import gate, make_ctx

pytestmark = pytest.mark.usefixtures("allow_unix_sockets")

EXITS_0 = "import sys; sys.exit(0)\n"
EXITS_1 = "import sys; sys.exit(1)\n"


def menu_ctx(tmp_path: Path) -> object:
    gates = {
        "lint": gate("lintmod", required=True),
        "unit": gate("unitmod", required=True),
        "zzz": gate("othermod", required=False),
    }
    modules = {"lintmod": EXITS_1, "unitmod": EXITS_0, "othermod": EXITS_0}
    return make_ctx(tmp_path, modules=modules, gates=gates)


def test_fail_fast_skips_every_gate_after_the_first_required_failure(tmp_path: Path) -> None:
    ctx = menu_ctx(tmp_path)
    run = run_gates(ctx, fail_fast=True)  # type: ignore[arg-type]
    status = {r.name: r.status for r in run.results}
    assert status["lint"] is GateStatus.FAIL
    assert status["unit"] is GateStatus.SKIPPED
    assert status["zzz"] is GateStatus.SKIPPED
    skipped = next(r for r in run.results if r.name == "unit")
    assert skipped.required
    assert "lint failed first" in skipped.summary
    assert not run.passed()
    assert "unit" not in run.outputs


def test_without_fail_fast_every_gate_runs(tmp_path: Path) -> None:
    ctx = menu_ctx(tmp_path)
    run = run_gates(ctx)  # type: ignore[arg-type]
    status = {r.name: r.status for r in run.results}
    assert (status["lint"], status["unit"], status["zzz"]) == (
        GateStatus.FAIL, GateStatus.PASS, GateStatus.PASS,
    )  # fmt: skip


def test_an_optional_failure_does_not_stop_the_build_gates(tmp_path: Path) -> None:
    gates = {"lint": gate("lintmod", required=False), "unit": gate("unitmod", required=True)}
    ctx = make_ctx(tmp_path, modules={"lintmod": EXITS_1, "unitmod": EXITS_0}, gates=gates)
    status = {r.name: r.status for r in run_gates(ctx, fail_fast=True).results}
    assert (status["lint"], status["unit"]) == (GateStatus.FAIL, GateStatus.PASS)


def test_a_failed_prepare_stops_a_fail_fast_run_at_once(tmp_path: Path) -> None:
    modules = {"unitmod": EXITS_0, "preparemod": EXITS_1}
    ctx = make_ctx(tmp_path, modules=modules, gates={"unit": gate("unitmod")})
    prepare = PrepareDef(run=(sys.executable, "-m", "preparemod"))
    cfg = ctx.cfg.model_copy(update={"prepare": prepare})
    run = run_gates(dataclasses.replace(ctx, cfg=cfg), fail_fast=True)
    status = {r.name: r.status for r in run.results}
    assert status["prepare"] is not GateStatus.PASS
    assert status["unit"] is GateStatus.SKIPPED


def test_build_gates_may_not_read_the_agent_config_home(tmp_path: Path) -> None:
    ctx = dataclasses.replace(
        make_ctx(tmp_path), runtime="/bin/srt", deny_read=(tmp_path / "agent-home",)
    )
    for kind in (ProcessKind.GATE, ProcessKind.PREPARE):
        profile = sandbox_for(ctx, kind, NetworkProfile.NONE)
        assert profile is not None
        assert tmp_path / "agent-home" in profile.deny_read
        assert ctx.home / ".claude" in profile.deny_read or kind is ProcessKind.PREPARE
