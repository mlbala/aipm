"""`aipm auto`: run the next step until the plan is built (ARCHITECTURE §7.3, ADR-0028).

The loop is the phase engine's `next_command`, one step at a time:

- `discover`, `design`, `plan` run as their commands do; a ready task (`aipm prompt T-…`) runs
  `aipm build`, which dispatches every ready task.
- `approve prd|design|plan` are the review gates G1-G3. Without `--yes`, `auto` pauses and asks;
  in a non-interactive run it exits 4 and names the command. With `--yes` it records the
  approval, as `aipm approve <artifact> --yes` does.
- `aipm trust`, a blocked plan (`aipm status`) and an uninitialized repository stop the loop.

`auto` never records trust (SECURITY.md §6 rule 4): it checks the execution surface before its
first step and exits 6 with `aipm trust` when it is not trusted, and the phase engine stops it
again at the trust gate when G2 changed the surface. Any step that fails stops the loop with that
step's exit code (4, 5, 6 and 8 among them) and the exact command to run next.
"""

from collections.abc import Callable
from dataclasses import dataclass, field
from enum import StrEnum
from pathlib import Path
from typing import Protocol

from aipm.app import phase as phase_view
from aipm.app.trust import require_trusted
from aipm.app.workspace import find_repo_root, require_initialized
from aipm.config.loader import load_config
from aipm.domain.errors import (
    AipmError,
    BudgetExceeded,
    HumanInputRequired,
    Interrupted,
    LockHeld,
    MissingCapability,
    PolicyViolation,
    UsageError,
    VerificationFailed,
)
from aipm.domain.ids import is_valid_id
from aipm.domain.phase import Phase, PhaseReport

MAX_STEPS = 50
"""A plan with more steps than this is not one `auto` run: it stops and says so."""


class StepKind(StrEnum):
    """What `auto` does with the phase engine's next command."""

    RUN = "run"
    GATE = "gate"
    STOP = "stop"
    DONE = "done"


@dataclass(frozen=True, slots=True)
class AutoStep:
    """One step: `name` is the aipm command to run (`discover`, `design`, `plan`, `approve`,
    `build`), `arg` its argument, `command` what a person would type, and for a stop the exit
    code and why."""

    kind: StepKind
    command: str
    name: str = ""
    arg: str | None = None
    reason: str = ""


@dataclass(frozen=True, slots=True)
class AutoOptions:
    """The command's flags. `interactive`: a gate may ask (the `approve` command shows its
    review and asks). `one_build`: stop after the first build (`--dry-run` or `--only`)."""

    yes: bool = False
    interactive: bool = False
    one_build: bool = False


@dataclass(slots=True)
class AutoResult:
    """The commands `auto` ran, in order, and the phase it reached."""

    ran: list[str] = field(default_factory=list[str])
    phase: str = ""

    def to_data(self) -> dict[str, object]:
        """The `--json` payload."""
        return {"ran": list(self.ran), "phase": self.phase}


class AutoSteps(Protocol):
    """How the CLI runs one step; it raises `AipmError` when the step fails."""

    def run(self, step: AutoStep, *, yes: bool) -> None:
        """Run `step` as its own command would. At a gate, `yes` records the approval without
        asking; otherwise the command shows its review and asks."""
        ...


_ERRORS: dict[int, type[AipmError]] = {
    int(cls.exit_code): cls
    for cls in (
        UsageError, VerificationFailed, HumanInputRequired, BudgetExceeded, PolicyViolation,
        LockHeld, MissingCapability, Interrupted,
    )
}  # fmt: skip


def step_failed(exit_code: int, command: str) -> AipmError:
    """The error that stops the loop when a step exited `exit_code`: the step has already
    said why; this keeps its exit code and names the command to run next."""
    cls = _ERRORS.get(exit_code, AipmError)
    return cls(
        f"aipm auto stopped: `{command}` exited {exit_code}",
        hint=f"Fix what `{command}` reported, then run `aipm auto` again.",
    )


_GATES = {"prd": "G1", "design": "G2", "plan": "G3"}


_RUN: dict[str, tuple[str, str | None]] = {
    "discover": ("discover", None),
    "design": ("design", None),
    "design --regenerate": ("design", "--regenerate"),
    "plan": ("plan", None),
}
_STOPS: dict[str, str] = {
    "trust": "the execution surface is not trusted",
    "init": "the repository is not initialized",
}


def next_step(report: PhaseReport) -> AutoStep:
    """Map the phase engine's next command to a step. Pure; any command it does not know
    stops the loop, so `auto` runs only what this table names."""
    command = report.next_command
    if command is None:
        if report.phase is Phase.BUILT:
            return AutoStep(StepKind.DONE, "")
        return _stop("aipm status", "the plan cannot go further", report)
    rest = command.removeprefix("aipm ") if command.startswith("aipm ") else ""
    words = rest.split()
    if rest in _RUN:
        name, arg = _RUN[rest]
        return AutoStep(StepKind.RUN, command, name, arg)
    if len(words) == 2 and words[0] == "approve" and words[1] in _GATES:
        return AutoStep(StepKind.GATE, command, "approve", words[1])
    if len(words) == 2 and words[0] == "prompt" and is_valid_id("task", words[1]):
        return AutoStep(StepKind.RUN, "aipm build", "build")
    reason = _STOPS.get(rest, "a person has to decide what happens next")
    return _stop(command, reason, report)


def _stop(command: str, reason: str, report: PhaseReport) -> AutoStep:
    detail = "; ".join(report.blockers)
    return AutoStep(StepKind.STOP, command, reason=f"{reason}: {detail}" if detail else reason)


def _stop_error(step: AutoStep) -> AipmError:
    hint = f"Run `{step.command}`, then `aipm auto` again."
    if step.command == "aipm trust":
        return PolicyViolation(
            f"aipm auto stopped: {step.reason}; it never records trust",
            hint="Review the surface with `aipm trust --show`, then run `aipm trust` and "
            "`aipm auto` again.",
        )
    if step.command == "aipm init":
        return UsageError(f"aipm auto stopped: {step.reason}", hint=hint)
    return HumanInputRequired(f"aipm auto stopped: {step.reason}", hint=hint)


def check_trust(project: Path | None) -> Path:
    """The repository root, if it is initialized and its execution surface is trusted; exit 6
    with the `aipm trust` hint otherwise. `auto` itself never records trust."""
    root = find_repo_root(project)
    require_initialized(root)
    try:
        require_trusted(root, load_config(root), command="auto")
    except PolicyViolation:
        raise PolicyViolation(
            "aipm auto runs the gate commands and coding agents of this repository, and you "
            "have not trusted them; auto never records trust",
            hint="Review them with `aipm trust --show`, then run `aipm trust` and `aipm auto`.",
        ) from None
    return root


def _phase(project: Path | None) -> PhaseReport:
    return phase_view.run(project).report


def run(
    project: Path | None,
    options: AutoOptions,
    steps: AutoSteps,
    *,
    report: Callable[[Path | None], PhaseReport] | None = None,
    trust: Callable[[Path | None], object] = check_trust,
) -> AutoResult:
    """Run steps until the plan is built, a gate pauses, or a step stops the loop.

    `report` and `trust` are seams for tests: the phase report, and the trust check that runs
    before anything else."""
    trust(project)
    derive = report or _phase
    result = AutoResult()
    last: tuple[str, str | None, tuple[str, ...]] | None = None
    for _ in range(MAX_STEPS):
        current = derive(project)
        result.phase = current.phase.value
        state = (current.phase.value, current.next_command, current.blockers)
        if state == last:
            raise HumanInputRequired(
                f"aipm auto stopped: `{current.next_command}` changed nothing (a gate that was "
                "not approved, or a step that needs you)",
                hint=f"Run `{current.next_command}` yourself to see what it needs.",
            )
        last = state
        step = next_step(current)
        if step.kind is StepKind.DONE:
            return result
        if step.kind is StepKind.STOP:
            raise _stop_error(step)
        if step.kind is StepKind.GATE and not options.yes and not options.interactive:
            raise HumanInputRequired(
                f"aipm auto paused at {_GATES[step.arg or '']}: it needs your review",
                hint=f"Review it, then run `{step.command} --yes` and `aipm auto`, or run "
                "`aipm auto --yes`.",
            )
        steps.run(step, yes=step.kind is StepKind.GATE and options.yes)
        result.ran.append(step.command)
        if options.one_build and step.name == "build":
            return result
    raise HumanInputRequired(
        f"aipm auto stopped after {MAX_STEPS} steps",
        hint="Run `aipm` to see the phase, then `aipm auto` again.",
    )
