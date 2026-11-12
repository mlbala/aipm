"""`aipm auto` (ARCHITECTURE §7.3, ADR-0028): the step table and the loop, with a fake phase
engine and fake steps. The end-to-end runs are in `tests/integration/test_auto_cli.py`; the
trust guarantees in `tests/security/test_auto_trust.py`."""

from pathlib import Path

import pytest

from aipm.app.auto import (
    MAX_STEPS,
    AutoOptions,
    AutoStep,
    StepKind,
    next_step,
    run,
    step_failed,
)
from aipm.domain.errors import AipmError, ExitCode, PolicyViolation
from aipm.domain.models import Phase
from aipm.domain.phase import PhaseReport


@pytest.mark.parametrize(
    ("command", "kind", "name", "arg"),
    [
        ("aipm discover", StepKind.RUN, "discover", None),
        ("aipm design", StepKind.RUN, "design", None),
        ("aipm design --regenerate", StepKind.RUN, "design", "--regenerate"),
        ("aipm plan", StepKind.RUN, "plan", None),
        ("aipm approve prd", StepKind.GATE, "approve", "prd"),
        ("aipm approve design", StepKind.GATE, "approve", "design"),
        ("aipm approve plan", StepKind.GATE, "approve", "plan"),
        ("aipm prompt T-004", StepKind.RUN, "build", None),
        ("aipm trust", StepKind.STOP, "", None),
        ("aipm init", StepKind.STOP, "", None),
        ("aipm status", StepKind.STOP, "", None),
        ("aipm approve context", StepKind.STOP, "", None),
        ("aipm prompt T-4; rm -rf /", StepKind.STOP, "", None),
        ("rm -rf /", StepKind.STOP, "", None),
    ],
)
def test_next_step_runs_only_what_its_table_names(
    command: str, kind: StepKind, name: str, arg: str | None
) -> None:
    step = next_step(PhaseReport(Phase.PLAN_DRAFT, next_command=command))
    assert (step.kind, step.name, step.arg) == (kind, name, arg)


def test_built_is_done_and_nothing_else_is() -> None:
    assert next_step(PhaseReport(Phase.BUILT)).kind is StepKind.DONE
    stuck = next_step(PhaseReport(Phase.BUILDING, blockers=("T-002 is blocked",)))
    assert stuck.kind is StepKind.STOP and "T-002 is blocked" in stuck.reason


class Engine:
    """A phase engine that moves one phase on per step it is told ran."""

    def __init__(self, commands: list[str | None]) -> None:
        self.commands = commands
        self.at = 0

    def report(self, _project: Path | None) -> PhaseReport:
        command = self.commands[min(self.at, len(self.commands) - 1)]
        phase = Phase.BUILT if command is None else Phase.PLAN_DRAFT
        return PhaseReport(phase, next_command=command)


class Steps:
    def __init__(self, engine: Engine, *, fail: dict[str, AipmError] | None = None,
                 stuck: bool = False) -> None:  # fmt: skip
        self.engine = engine
        self.fail = fail or {}
        self.stuck = stuck
        self.ran: list[tuple[str, bool]] = []

    def run(self, step: AutoStep, *, yes: bool) -> None:
        self.ran.append((step.command, yes))
        if step.command in self.fail:
            raise self.fail[step.command]
        if not self.stuck:
            self.engine.at += 1


FLOW: list[str | None] = [
    "aipm discover", "aipm approve prd", "aipm design", "aipm approve design", "aipm plan",
    "aipm approve plan", "aipm prompt T-001", None,
]  # fmt: skip


def trusted(_project: Path | None) -> None:
    return None


def go(engine: Engine, steps: Steps, **options: bool) -> list[str]:
    result = run(None, AutoOptions(**options), steps, report=engine.report, trust=trusted)
    return result.ran


def test_yes_runs_every_step_to_built_and_approves_the_gates() -> None:
    engine = Engine(FLOW)
    steps = Steps(engine)
    ran = go(engine, steps, yes=True)
    assert ran == ["aipm discover", "aipm approve prd", "aipm design", "aipm approve design",
                   "aipm plan", "aipm approve plan", "aipm build"]  # fmt: skip
    gates = [yes for command, yes in steps.ran if command.startswith("aipm approve")]
    assert gates == [True, True, True]
    assert all(not yes for command, yes in steps.ran if not command.startswith("aipm approve"))


def test_a_gate_pauses_a_non_interactive_run_with_exit_4() -> None:
    engine = Engine(FLOW)
    steps = Steps(engine)
    with pytest.raises(AipmError) as info:
        go(engine, steps)
    assert info.value.exit_code is ExitCode.HUMAN_INPUT_REQUIRED
    assert "G1" in info.value.message and "aipm approve prd --yes" in (info.value.hint or "")
    assert steps.ran == [("aipm discover", False)]


def test_an_interactive_gate_asks_through_its_own_command() -> None:
    engine = Engine(FLOW)
    steps = Steps(engine)
    go(engine, steps, interactive=True)
    assert ("aipm approve prd", False) in steps.ran


def test_a_declined_gate_stops_the_loop_with_exit_4() -> None:
    engine = Engine(["aipm approve design"])
    steps = Steps(engine, stuck=True)
    with pytest.raises(AipmError) as info:
        go(engine, steps, interactive=True)
    assert info.value.exit_code is ExitCode.HUMAN_INPUT_REQUIRED
    assert len(steps.ran) == 1


@pytest.mark.parametrize("code", [4, 5, 6, 8, 3, 7, 130, 2])
def test_a_failing_step_stops_with_its_exit_code_and_the_next_command(code: int) -> None:
    engine = Engine(FLOW)
    steps = Steps(engine, fail={"aipm design": step_failed(code, "aipm design")})
    with pytest.raises(AipmError) as info:
        go(engine, steps, yes=True)
    assert int(info.value.exit_code) == code
    assert "aipm design" in info.value.message
    assert steps.ran[-1] == ("aipm design", False)


def test_an_unknown_exit_code_is_an_internal_error() -> None:
    assert step_failed(99, "aipm plan").exit_code is ExitCode.INTERNAL


@pytest.mark.parametrize(
    ("command", "code"),
    [("aipm trust", ExitCode.SECURITY_VIOLATION), ("aipm init", ExitCode.USAGE),
     ("aipm status", ExitCode.HUMAN_INPUT_REQUIRED)],
)  # fmt: skip
def test_stops_name_the_command_to_run(command: str, code: ExitCode) -> None:
    engine = Engine([command])
    with pytest.raises(AipmError) as info:
        go(engine, Steps(engine), yes=True)
    assert info.value.exit_code is code
    assert command in f"{info.value.message} {info.value.hint}"


def test_the_trust_gate_says_auto_never_records_trust() -> None:
    engine = Engine(["aipm trust"])
    with pytest.raises(PolicyViolation) as info:
        go(engine, Steps(engine), yes=True)
    assert "never records trust" in info.value.message


def test_trust_is_checked_before_any_step() -> None:
    engine = Engine(FLOW)
    steps = Steps(engine)

    def untrusted(_project: Path | None) -> None:
        raise PolicyViolation("not trusted")

    with pytest.raises(PolicyViolation):
        run(None, AutoOptions(yes=True), steps, report=engine.report, trust=untrusted)
    assert steps.ran == []


def test_a_step_that_changes_nothing_stops_the_loop() -> None:
    engine = Engine(["aipm discover"])
    steps = Steps(engine, stuck=True)
    with pytest.raises(AipmError, match="changed nothing") as info:
        go(engine, steps, yes=True)
    assert info.value.exit_code is ExitCode.HUMAN_INPUT_REQUIRED
    assert len(steps.ran) == 1


def test_the_loop_has_a_step_limit() -> None:
    commands: list[str | None] = ["aipm discover", "aipm plan"] * MAX_STEPS
    engine = Engine(commands)
    with pytest.raises(AipmError, match=f"after {MAX_STEPS} steps"):
        go(engine, Steps(engine), yes=True)


def test_one_build_stops_after_the_build() -> None:
    engine = Engine(["aipm prompt T-001", "aipm prompt T-002", None])
    steps = Steps(engine)
    assert go(engine, steps, yes=True, one_build=True) == ["aipm build"]
