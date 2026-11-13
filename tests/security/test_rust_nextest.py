"""The rust-cargo unit gate is judged on a report, not on exit 0 (ADR-0030).

Step 08's security review (F-1): `cargo test` writes no report, so the required unit gate passed
on exit code alone, and a test calling `std::process::exit(0)` (or a `build.rs` killing cargo
under `srt`) passed the task with failing tests. The template now runs `cargo nextest run` with a
configuration aipm writes outside the work tree, which sends nextest's JUnit report to
`{report_file}`. These tests use a stub `cargo` on PATH with the shipped template's own argv.
"""

import sys
import tomllib
from datetime import UTC, datetime
from pathlib import Path

import pytest

from aipm.app.project_context import agent_gates
from aipm.config.schema import Config
from aipm.config.stacks import load_stack
from aipm.domain.errors import PolicyViolation
from aipm.domain.models import (
    AcceptanceCriterion,
    ChangeSet,
    GateDef,
    GateStatus,
    GateWorkspace,
    Task,
    TaskSize,
    TaskType,
)
from aipm.gates import command_gate
from aipm.gates.command_gate import run_command_gate
from aipm.gates.context import GateContext
from aipm.security.command_policy import (
    CommandPolicy,
    check_argv,
    compile_gate,
    nextest_config_path,
)
from aipm.security.redact import Redactor

pytestmark = pytest.mark.usefixtures("allow_unix_sockets")

PASSING = (
    '<?xml version="1.0"?><testsuites name="nextest-run" tests="2"><testsuite name="demo">'
    '<testcase classname="demo" name="tests::a"/><testcase classname="demo::it" name="b"/>'
    "</testsuite></testsuites>"
)
FAILING = PASSING.replace('name="b"/>', 'name="b"><failure message="boom"/></testcase>')

# The stub reads the --config-file aipm passed, checks it, and writes the scripted report
# (or none) to the JUnit path it names, then exits 0 whatever happened: as a test that calls
# std::process::exit(0), or srt after SIGTERM, would.
STUB = """
import sys, tomllib
from pathlib import Path
args = sys.argv[1:]
assert args[:4] == ["nextest", "run", "--locked", "--offline"], args
config = Path(args[args.index("--config-file") + 1])
doc = tomllib.loads(config.read_text(encoding="utf-8"))
junit = Path(doc["profile"]["default"]["junit"]["path"])
report = {report!r}
if report is not None:
    junit.write_text(report, encoding="utf-8")
sys.exit(0)
"""


def stub_cargo(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, report: str | None) -> None:
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir(exist_ok=True)
    script = tmp_path / "stub_cargo.py"
    script.write_text(STUB.format(report=report), encoding="utf-8")
    cargo = bin_dir / "cargo"
    cargo.write_text(f'#!/bin/sh\nexec "{sys.executable}" -I "{script}" "$@"\n', encoding="utf-8")
    cargo.chmod(0o755)
    monkeypatch.setenv("PATH", f"{bin_dir}:/usr/bin:/bin")


def rust_ctx(tmp_path: Path) -> GateContext:
    stack = load_stack("rust-cargo")
    repo = tmp_path / "repo"
    repo.mkdir()
    temp = tmp_path / "attempt"
    temp.mkdir(mode=0o700)
    cfg = Config.model_validate(stack.model_dump(mode="json"))
    criteria = [AcceptanceCriterion(id="AC-T001-1", text="x")]
    task = Task(id="T-001", title="t", type=TaskType.FEATURE, owns_files=["src/**"],
                acceptance=criteria, size=TaskSize.S)  # fmt: skip
    return GateContext(
        ws=GateWorkspace(root=repo, temp_dir=temp, base_sha="a" * 40),
        task=task, cfg=cfg, changes=ChangeSet("a" * 40), redactor=Redactor({}),
        home=tmp_path / "home", now=datetime.now(UTC), runtime=None,
    )  # fmt: skip


def run_unit(ctx: GateContext) -> command_gate.CommandOutcome:
    return run_command_gate("unit", ctx.cfg.gates["unit"], ctx, paths=[], required=True)


# ---------------------------------------------------------------- the gate


def test_cargo_exiting_0_without_running_tests_does_not_pass(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    stub_cargo(tmp_path, monkeypatch, report=None)
    out = run_unit(rust_ctx(tmp_path))
    assert out.result.status is GateStatus.FAIL
    assert "no test report" in out.result.summary


def test_cargo_exiting_0_with_a_failing_test_does_not_pass(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    stub_cargo(tmp_path, monkeypatch, report=FAILING)
    out = run_unit(rust_ctx(tmp_path))
    assert out.result.status is GateStatus.FAIL
    assert "shows failures" in out.result.summary


def test_a_report_with_no_tests_does_not_pass(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    stub_cargo(tmp_path, monkeypatch, report='<testsuites name="nextest-run" tests="0"/>')
    out = run_unit(rust_ctx(tmp_path))
    assert out.result.status is GateStatus.FAIL
    assert "no tests ran" in out.result.summary


def test_a_passing_report_passes(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    stub_cargo(tmp_path, monkeypatch, report=PASSING)
    out = run_unit(rust_ctx(tmp_path))
    assert out.result.status is GateStatus.PASS, out.result.summary
    assert out.result.summary == "2 passed, 0 failed, 0 skipped"


def test_the_nextest_config_lives_outside_the_work_tree_and_replaces_a_planted_one(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    stub_cargo(tmp_path, monkeypatch, report=PASSING)
    ctx = rust_ctx(tmp_path)
    monkeypatch.setattr(command_gate.secrets, "token_hex", lambda _n: "0123456789abcdef")
    report = ctx.ws.temp_dir / "report-unit-0123456789abcdef"
    config = nextest_config_path(report)
    config.write_text('[profile.default.junit]\npath = "/elsewhere.xml"\n', encoding="utf-8")
    out = run_unit(ctx)
    assert out.result.status is GateStatus.PASS, out.result.summary
    doc = tomllib.loads(config.read_text(encoding="utf-8"))
    assert doc["profile"]["default"]["junit"]["path"] == str(report)
    assert doc["profile"]["default"]["retries"] == 0
    store = Path(doc["store"]["dir"])
    assert store.is_absolute() and store.parent == ctx.ws.temp_dir
    assert config.stat().st_mode & 0o077 == 0
    assert not any(ctx.ws.root.iterdir())  # nothing written into the work tree


def test_the_shipped_unit_gate_is_nextest_with_aipms_config() -> None:
    gate = load_stack("rust-cargo").gates["unit"]
    assert gate.required
    assert gate.run is not None and gate.run[:3] == ("cargo", "nextest", "run")
    assert gate.run[-2:] == ("--config-file", "{nextest_config}")


def test_agents_see_an_empty_nextest_config() -> None:
    """Manual mode (ADR-0017): the agent's copy uses nextest's defaults and writes no report."""
    cfg = Config.model_validate(load_stack("rust-cargo").model_dump(mode="json"))
    unit = next(g for g in agent_gates(cfg) if g.name == "unit")
    assert unit.argv is not None and unit.argv[-2:] == ("--config-file", "/dev/null")


# ---------------------------------------------------------------- the command policy

NEXTEST = ("cargo", "nextest", "run", "--locked", "--offline", "--config-file")


@pytest.fixture
def policy() -> CommandPolicy:
    return CommandPolicy(allowed_prefixes=(NEXTEST,), test_roots=("tests",))


def unit(*extra: str) -> GateDef:
    return GateDef(run=(*NEXTEST, "{nextest_config}", *extra), required=True)


def test_nextest_config_defaults_to_the_reports_sibling(policy: CommandPolicy) -> None:
    report = Path("/aipm-attempt/report-unit-1")
    argv = compile_gate(unit(), paths=[], policy=policy, report_file=report)
    assert argv[-1] == "/aipm-attempt/report-unit-1.nextest.toml"
    named = compile_gate(
        unit(), paths=[], policy=policy, report_file=report, nextest_config=Path("/dev/null")
    )
    assert named[-1] == "/dev/null"


def test_nextest_config_rules(policy: CommandPolicy) -> None:
    with pytest.raises(PolicyViolation, match=r"\{nextest_config\}.*no report file"):
        compile_gate(unit(), paths=[], policy=policy)
    with pytest.raises(PolicyViolation, match="absolute"):
        compile_gate(unit(), paths=[], policy=policy, nextest_config=Path("n.toml"))
    with pytest.raises(PolicyViolation, match="whole argv element"):
        compile_gate(
            GateDef(run=(*NEXTEST, "x{nextest_config}")),
            paths=[],
            policy=policy,
            report_file=Path("/r"),
        )


@pytest.mark.parametrize(
    "flag",
    ["--archive-file", "--archive-file=a.tar.zst", "--binaries-metadata", "--cargo-metadata=m"],
)
def test_nextest_may_not_run_prebuilt_binaries(policy: CommandPolicy, flag: str) -> None:
    with pytest.raises(PolicyViolation, match="runs other programs"):
        check_argv((*NEXTEST, "/c.toml", flag), policy, stage="gate")


@pytest.mark.parametrize(
    "argv",
    [
        ("cargo", "nextest", "list", "run"),
        ("cargo", "test", "nextest", "run"),
        ("cargo", "nextest", "run", "--", "run"),
        ("cargo", "--locked", "nextest", "run"),
    ],
)
def test_only_cargo_nextest_run_may_say_run(argv: tuple[str, ...]) -> None:
    """`cargo run` itself cannot even be an allowed prefix (tests/security/test_command_policy)."""
    anything = CommandPolicy(allowed_prefixes=(("cargo", "nextest"), ("cargo", "test"),
                                               ("cargo", "--locked", "nextest")))  # fmt: skip
    with pytest.raises(PolicyViolation, match="runs or installs"):
        check_argv(argv, anything, stage="gate")


def test_cargo_nextest_run_with_aipms_config_passes(policy: CommandPolicy) -> None:
    argv = (*NEXTEST, "/aipm-attempt/report-unit-1.nextest.toml")
    assert check_argv(argv, policy, stage="gate") == argv
    with pytest.raises(PolicyViolation, match="--config"):
        check_argv((*argv, "--config", "target.x.runner='y'"), policy, stage="gate")


@pytest.mark.parametrize("flag", ["--tool-config-file", "--tool-config-file=x:/t.toml"])
def test_nextest_may_not_load_a_tool_config(policy: CommandPolicy, flag: str) -> None:
    """A tool configuration can define setup and wrapper scripts (step 08 re-review)."""
    with pytest.raises(PolicyViolation, match="runs other programs"):
        check_argv((*NEXTEST, "/c.toml", flag), policy, stage="gate")
