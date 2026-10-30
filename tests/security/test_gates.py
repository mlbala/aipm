"""Command gates and the gate runner (ARCHITECTURE §13.2; SECURITY.md §8, §10 rule 5, §14.3).

Gate processes see no secret in their environment; a report planted in the work tree or at the
report path before the run is ignored; a test that kills its own runner does not pass, even
under a sandbox that exits 0 on SIGTERM; a gate that forks a daemon is killed with its whole
process group at the timeout; 50 MB of output is capped. The network test needs a real `srt`
and is skipped without one (run it locally: `npm install -g @anthropic-ai/sandbox-runtime`,
then `uv run pytest tests/security/test_gates.py -k network`).
"""

import os
import shutil
import sys
import time
from datetime import UTC, datetime
from pathlib import Path

import pytest
import pytest_socket

from aipm.config.schema import Config
from aipm.domain.errors import PolicyViolation
from aipm.domain.models import (
    AcceptanceCriterion,
    ChangeSet,
    GateDef,
    GateResult,
    GateStatus,
    GateWorkspace,
    Task,
    TaskSize,
    TaskType,
)
from aipm.gates import command_gate
from aipm.gates.command_gate import run_command_gate
from aipm.gates.context import GateContext, owned_paths
from aipm.gates.runner import GateRun, gate_order, run_gates
from aipm.security.redact import Redactor
from tests.conftest import FakeSecrets

PY = sys.executable
STUB_BIN = Path(__file__).resolve().parents[1] / "fakes" / "bin"
PASSING_JUNIT = (
    '<?xml version="1.0"?><testsuites><testsuite name="s" tests="1">'
    '<testcase classname="tests.test_a" name="test_x"/></testsuite></testsuites>'
)

pytestmark = pytest.mark.usefixtures("allow_unix_sockets")


def make_ctx(tmp_path: Path, *, modules: dict[str, str] | None = None,
             gates: dict[str, GateDef] | None = None, runtime: str | None = None,
             owns: list[str] | None = None) -> GateContext:  # fmt: skip
    repo = tmp_path / "repo"
    repo.mkdir(exist_ok=True)
    for name, body in (modules or {}).items():
        (repo / f"{name}.py").write_text(body, encoding="utf-8")
    temp = tmp_path / "attempt"
    temp.mkdir(mode=0o700, exist_ok=True)
    cfg = Config.model_validate(
        {
            "allowed_executables": [[PY, "-m", name] for name in (*(modules or {}), "ruff")],
            "gates": {k: v.model_dump(mode="json", exclude_none=True)
                      for k, v in (gates or {}).items()},
        }
    )  # fmt: skip
    criteria = [AcceptanceCriterion(id="AC-T001-1", text="x")]
    task = Task(id="T-001", title="t", type=TaskType.FEATURE, owns_files=owns or ["src/**"],
                acceptance=criteria, size=TaskSize.S)  # fmt: skip
    return GateContext(
        ws=GateWorkspace(root=repo, temp_dir=temp, base_sha="a" * 40),
        task=task, cfg=cfg, changes=ChangeSet("a" * 40), redactor=Redactor({}),
        home=tmp_path / "home", now=datetime.now(UTC), runtime=runtime,
    )  # fmt: skip


def gate(*args: str, required: bool = True) -> GateDef:
    return GateDef(run=(PY, "-m", *args), required=required)


# ---------------------------------------------------------------- environment


ENVDUMP = """
import os, sys
with open(sys.argv[1], "w") as f:
    for k, v in sorted(os.environ.items()):
        f.write(f"{k}={v}\\n")
"""


def test_gate_processes_see_no_secret(tmp_path: Path, fake_secrets: FakeSecrets) -> None:
    ctx = make_ctx(tmp_path, modules={"envdump": ENVDUMP})
    out = run_command_gate("dump", gate("envdump", "env.txt"), ctx, paths=[], required=True)
    assert out.result.status is GateStatus.PASS, out.result.summary
    dumped = (ctx.root / "env.txt").read_text(encoding="utf-8")
    fake_secrets.assert_absent(dumped)
    names = {line.split("=", 1)[0] for line in dumped.splitlines()}
    assert not {n for n in names if "KEY" in n or "TOKEN" in n or "SECRET" in n}
    assert f"PYTHONPYCACHEPREFIX={ctx.ws.temp_dir / 'pycache'}" in dumped
    assert "PYTHONDONTWRITEBYTECODE=1" in dumped


# ---------------------------------------------------------------- reports

NO_REPORT = "import sys\nsys.exit(0)\n"
WRITES_REPORT = f"import sys\nopen(sys.argv[1], 'w').write({PASSING_JUNIT!r})\n"


def test_a_report_planted_in_the_work_tree_is_ignored(tmp_path: Path) -> None:
    ctx = make_ctx(tmp_path, modules={"noreport": NO_REPORT})
    (ctx.root / "report.xml").write_text(PASSING_JUNIT, encoding="utf-8")
    (ctx.root / "junit.xml").write_text(PASSING_JUNIT, encoding="utf-8")
    out = run_command_gate("unit", gate("noreport", "{report_file}"), ctx, paths=[], required=True)
    assert out.result.status is GateStatus.FAIL
    assert "no test report" in out.result.summary
    assert out.report is None


def test_a_report_planted_at_the_path_before_the_run_is_deleted(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    ctx = make_ctx(tmp_path, modules={"noreport": NO_REPORT})
    monkeypatch.setattr(command_gate.secrets, "token_hex", lambda _n: "0123456789abcdef")
    planted = ctx.ws.temp_dir / "report-unit-0123456789abcdef"
    planted.write_text(PASSING_JUNIT, encoding="utf-8")
    out = run_command_gate("unit", gate("noreport", "{report_file}"), ctx, paths=[], required=True)
    assert out.result.status is GateStatus.FAIL
    assert not planted.exists()


def test_a_written_report_is_read_and_judged(tmp_path: Path) -> None:
    ctx = make_ctx(tmp_path, modules={"good": WRITES_REPORT})
    out = run_command_gate("unit", gate("good", "{report_file}"), ctx, paths=[], required=True)
    assert out.result.status is GateStatus.PASS
    assert out.result.summary == "1 passed, 0 failed, 0 skipped"


def test_a_report_with_no_tests_or_failures_fails(tmp_path: Path) -> None:
    empty = "<testsuites/>"
    failing = PASSING_JUNIT.replace("/></testsuite>", "><failure/></testcase></testsuite>")
    modules = {
        "empty": f"import sys\nopen(sys.argv[1], 'w').write({empty!r})\n",
        "failing": f"import sys\nopen(sys.argv[1], 'w').write({failing!r})\n",
        "dtd": "import sys\nopen(sys.argv[1], 'w').write('<!DOCTYPE x [<!ENTITY a \"b\">]><x/>')\n",
    }
    ctx = make_ctx(tmp_path, modules=modules)
    for name, expected in (("empty", "no tests ran"), ("failing", "shows failures"),
                           ("dtd", "DOCTYPE")):  # fmt: skip
        out = run_command_gate("unit", gate(name, "{report_file}"), ctx, paths=[], required=True)
        assert out.result.status is GateStatus.FAIL, name
        assert expected in out.result.summary, out.result.summary


KILLS_ITSELF = "import os, signal\nos.kill(os.getpid(), signal.SIGTERM)\n"


def test_a_test_that_kills_its_runner_never_passes(tmp_path: Path) -> None:
    ctx = make_ctx(tmp_path, modules={"suicide": KILLS_ITSELF})
    out = run_command_gate("unit", gate("suicide", "{report_file}"), ctx, paths=[], required=True)
    assert out.result.status is GateStatus.FAIL


def test_exit_0_from_a_sandbox_after_sigterm_is_not_a_pass(tmp_path: Path) -> None:
    """srt 0.0.81 exits 0 when its command dies of SIGTERM (ADR-0020)."""
    lenient = tmp_path / "lenient-srt"
    lenient.write_text('#!/bin/sh\nshift 3\n"$@"\nexit 0\n', encoding="utf-8")
    lenient.chmod(0o755)
    ctx = make_ctx(tmp_path, modules={"suicide": KILLS_ITSELF}, runtime=str(lenient))
    out = run_command_gate("unit", gate("suicide", "{report_file}"), ctx, paths=[], required=True)
    assert out.result.status is GateStatus.FAIL
    assert "no test report" in out.result.summary


# ---------------------------------------------------------------- timeouts, daemons, output

FORKS_A_DAEMON = """
import os, sys, time
pid = os.fork()
if pid == 0:
    time.sleep(120)
    os._exit(0)
open(sys.argv[1], "w").write(str(pid))
time.sleep(120)
"""


def _alive(pid: int) -> bool:
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    return True


def test_a_gate_and_its_daemon_are_killed_at_the_timeout(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(command_gate, "GATE_TIMEOUT_S", 1.5)
    ctx = make_ctx(tmp_path, modules={"daemon": FORKS_A_DAEMON})
    started = time.monotonic()
    out = run_command_gate("unit", gate("daemon", "pid.txt"), ctx, paths=[], required=True)
    assert time.monotonic() - started < 15
    assert out.result.status is GateStatus.ERROR
    assert "timed out" in out.result.summary
    child = int((ctx.root / "pid.txt").read_text(encoding="utf-8"))
    deadline = time.monotonic() + 5
    while _alive(child) and time.monotonic() < deadline:
        time.sleep(0.05)
    assert not _alive(child), "the forked daemon outlived the gate"


def test_50_mb_of_output_is_capped(tmp_path: Path) -> None:
    loud = "import sys\nchunk = 'x' * 1_048_576\nfor _ in range(50):\n    sys.stdout.write(chunk)\n"
    ctx = make_ctx(tmp_path, modules={"loud": loud})
    out = run_command_gate("lint", gate("loud"), ctx, paths=[], required=True)
    assert out.result.status is GateStatus.PASS
    assert "output cut" in out.result.summary
    assert len(out.result.output) < 100_000
    assert len(out.full_output) <= 2 * command_gate.MAX_OUTPUT_BYTES + 16


def test_gate_output_is_redacted(tmp_path: Path) -> None:
    leak = "print('token ghp_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa')\nraise SystemExit(1)\n"
    ctx = make_ctx(tmp_path, modules={"leak": leak})
    out = run_command_gate("lint", gate("leak"), ctx, paths=[], required=True)
    assert out.result.status is GateStatus.FAIL
    assert "ghp_aaaa" not in out.full_output
    assert "ghp_aaaa" not in out.result.output + out.result.summary


# ---------------------------------------------------------------- argv and paths


def test_argv0_is_resolved_as_the_trust_store_resolves_it(tmp_path: Path) -> None:
    ctx = make_ctx(tmp_path)
    (ctx.root / "bin").mkdir()
    tool = ctx.root / "bin" / "ruff"
    tool.write_text("#!/bin/sh\n", encoding="utf-8")
    tool.chmod(0o755)
    assert command_gate.resolve_program(str(tool), ctx.root) == str(tool)
    assert command_gate.resolve_program("no-such-program-x", ctx.root) == "no-such-program-x"


def test_owned_paths_expand_and_refuse_links_out(tmp_path: Path) -> None:
    ctx = make_ctx(tmp_path, owns=["src/**", "lib/a.py", "pkg/*.py", "missing/**"])
    for rel in ("src/x.py", "lib/a.py", "pkg/b.py", "pkg/c.txt"):
        (ctx.root / rel).parent.mkdir(parents=True, exist_ok=True)
        (ctx.root / rel).write_text("1", encoding="utf-8")
    assert owned_paths(ctx.root, ctx.task) == ["lib/a.py", "pkg/b.py", "src"]
    (ctx.root / "lib" / "a.py").unlink()
    (ctx.root / "lib" / "a.py").symlink_to(tmp_path)
    with pytest.raises(PolicyViolation):
        owned_paths(ctx.root, ctx.task)


def test_a_gate_with_no_owned_path_is_skipped(tmp_path: Path) -> None:
    ctx = make_ctx(tmp_path, gates={"lint": gate("ruff", "check", "{paths}")})
    run = run_gates(ctx)
    assert [(r.name, r.status) for r in run.results] == [("lint", GateStatus.SKIPPED)]
    assert run.passed() is False


# ---------------------------------------------------------------- the runner


def test_gate_order() -> None:
    names = ["ac_review", "deps", "e2e", "unit", "secrets", "lint", "ac_trace", "types", "sast"]
    assert gate_order(names) == ["secrets", "lint", "types", "unit", "e2e", "ac_trace", "sast",
                                 "deps", "ac_review"]  # fmt: skip


def test_a_gate_the_task_names_that_is_not_in_the_menu_is_an_error(tmp_path: Path) -> None:
    ctx = make_ctx(tmp_path)
    ctx = GateContext(**{**{f: getattr(ctx, f) for f in ("ws", "cfg", "changes", "redactor",
                                                         "home", "now")},
                         "task": ctx.task.model_copy(update={"gates": ["e2e"]})})  # fmt: skip
    run = run_gates(ctx)
    assert [(r.name, r.status, r.required) for r in run.results] == [
        ("e2e", GateStatus.ERROR, True)
    ]


def test_a_failed_prepare_stops_the_command_gates(tmp_path: Path) -> None:
    ctx = make_ctx(tmp_path, modules={"fails": "raise SystemExit(3)\n"},
                   gates={"lint": gate("fails")})  # fmt: skip
    cfg = ctx.cfg.model_copy(update={"prepare": Config.model_validate(
        {"prepare": {"run": [PY, "-m", "fails"]}}).prepare})  # fmt: skip
    ctx = GateContext(**{**{f: getattr(ctx, f) for f in ("ws", "task", "changes", "redactor",
                                                         "home", "now")}, "cfg": cfg})  # fmt: skip
    run = run_gates(ctx)
    assert [(r.name, r.status) for r in run.results] == [
        ("prepare", GateStatus.FAIL),
        ("lint", GateStatus.ERROR),
    ]


def test_passed_needs_every_required_gate_and_no_veto() -> None:
    ok = GateResult(name="unit", status=GateStatus.PASS, required=True)
    optional_fail = GateResult(name="format", status=GateStatus.FAIL, required=False)
    veto = GateResult(name="ac_review", status=GateStatus.FAIL, required=False)
    assert GateRun(results=[ok, optional_fail]).passed()
    assert not GateRun(results=[ok, veto]).passed()
    skipped = GateResult(name="sast", status=GateStatus.SKIPPED, required=True)
    assert not GateRun(results=[ok, skipped]).passed()


# ---------------------------------------------------------------- the real sandbox

REAL_SRT = shutil.which("srt")
NETWORK = """
import socket, sys
try:
    socket.create_connection(("example.com", 80), timeout=5).close()
except OSError:
    sys.exit(0)
sys.exit(1)
"""


@pytest.mark.skipif(
    REAL_SRT is None or Path(REAL_SRT).parent == STUB_BIN,
    reason="needs the real srt (npm install -g @anthropic-ai/sandbox-runtime)",
)
def test_the_gate_network_profile_blocks_outbound_connections(tmp_path: Path) -> None:
    pytest_socket.enable_socket()
    assert REAL_SRT is not None
    ctx = make_ctx(tmp_path, modules={"net": NETWORK}, runtime=REAL_SRT)
    out = run_command_gate("net", gate("net"), ctx, paths=[], required=True)
    assert out.result.status is GateStatus.PASS, out.full_output
