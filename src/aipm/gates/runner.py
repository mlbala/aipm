"""The gate runner (C-15, ARCHITECTURE §13.2).

1. `prepare`, with the `registries` network profile, when a command gate will run.
2. The gates in the order secrets, lint, format, types, unit, ac_trace, sast, deps, ac_review;
   any other menu gate runs after `unit`. `verify` runs them all (no fail-fast).
3. Command gates go through `compile_gate` → `sandbox.wrap` → `run_safe` with no network.

A gate counts as required when the menu says so or the task names it. A gate the task names
that is not in the menu is an error. `hold_prepare` stops the prepare step (and so every command
gate) when the post-change checks found a dependency the policy refused: prepare would install
it (red-team v0.2, RT02-4). The AC reviewer is not asked when a secrets gate of this run did not
pass, or when a gate changed a file of the diff, so a diff that may hold a secret never goes to
the LLM (RT02-5).

`GateRun` holds the report, the full (redacted) output of each gate for the run directory, the
gates whose scanner was missing, and what the AC reviewer reported.
"""

from collections.abc import Sequence
from dataclasses import dataclass, field

from aipm.domain.models import BuiltinGate, GateDef, GateReport, GateResult, GateStatus
from aipm.gates.builtin import BuiltinOutcome, ac_review, ac_trace, deps, sast, secrets
from aipm.gates.builtin.ac_review import Reviewer
from aipm.gates.command_gate import run_command_gate, run_prepare
from aipm.gates.context import GateContext, owned_paths
from aipm.gates.reports import TestReport
from aipm.security.paths import SafeRelPath

GATE_ORDER: tuple[str, ...] = (
    "secrets", "lint", "format", "types", "unit", "ac_trace", "sast", "deps", "ac_review",
)  # fmt: skip
"""Cheap gates first, then `ac_review` last (ARCHITECTURE §13.2)."""


@dataclass(slots=True)
class GateRun:
    """Everything one run of the gates produced."""

    results: list[GateResult] = field(default_factory=list[GateResult])
    outputs: dict[str, str] = field(default_factory=dict[str, str])
    missing_tools: list[str] = field(default_factory=list[str])
    injection: tuple[str, ...] = ()
    overridden: tuple[str, ...] = ()

    def report(self, task_id: str) -> GateReport:
        """The results as a gate report (run id and attempt are set by the caller)."""
        return GateReport(task=task_id, gates=list(self.results))

    def passed(self) -> bool:
        """Every required gate passed, and the AC reviewer vetoed nothing (ADR-0007)."""
        for result in self.results:
            if result.required and result.status is not GateStatus.PASS:
                return False
            if result.name == ac_review.NAME and result.status is GateStatus.FAIL:
                return False
        return True


def gate_order(names: Sequence[str]) -> list[str]:
    """The run order: the known gates in `GATE_ORDER`, any other right after `unit`."""
    unit = GATE_ORDER.index("unit")

    def key(name: str) -> tuple[float, str]:
        return (GATE_ORDER.index(name) if name in GATE_ORDER else unit + 0.5, name)

    return sorted(set(names), key=key)


def _error(name: str, summary: str, *, required: bool) -> GateResult:
    return GateResult(name=name, status=GateStatus.ERROR, required=required, summary=summary)


@dataclass(slots=True)
class _Attempt:
    """The state shared while one attempt's gates run."""

    ctx: GateContext
    reviewer: Reviewer | None
    reviewer_unavailable: str
    override_ac: str | None
    run: GateRun = field(default_factory=GateRun)
    prepare_ok: bool = True
    prepare_why: str = "the prepare step failed"
    report: TestReport | None = None

    def command(self, name: str, gate: GateDef, paths: list[SafeRelPath], required: bool) -> None:
        assert gate.run is not None  # noqa: S101 - only command gates come here
        if not self.prepare_ok:
            self.run.results.append(_error(name, f"not run: {self.prepare_why}", required=required))
            return
        if "{paths}" in gate.run and not paths:
            skipped = GateResult(name=name, status=GateStatus.SKIPPED, required=required,
                                 summary="no owned path exists")  # fmt: skip
            self.run.results.append(skipped)
            return
        outcome = run_command_gate(name, gate, self.ctx, paths=paths, required=required)
        self.run.results.append(outcome.result)
        self.run.outputs[name] = outcome.full_output
        if outcome.report is not None and (self.report is None or name == "unit"):
            self.report = outcome.report

    def builtin(self, name: str, gate: GateDef, required: bool) -> None:
        ctx = self.ctx
        built: BuiltinOutcome
        if gate.builtin is BuiltinGate.GITLEAKS:
            built = secrets.run(ctx, required=required)
        elif gate.builtin is BuiltinGate.SEMGREP:
            built = sast.run(ctx, gate, name=name, required=required)
        elif gate.builtin is BuiltinGate.OSV:
            built = deps.run(ctx, gate, name=name, required=required)
        elif gate.builtin is BuiltinGate.AC_TRACE:
            built = ac_trace.run(ctx, self.report, required=required)
        else:
            review = ac_review.run(
                ctx,
                self.reviewer,
                self.run.results,
                required=required,
                override_ac=self.override_ac,
                unavailable=self.reviewer_unavailable,
                hold=self.review_hold(),
            )
            built = review.gate
            self.run.injection = review.injection
            self.run.overridden = review.overridden
        self.run.results.append(built.result.model_copy(update={"name": name}))
        self.run.outputs[name] = built.full_output
        if built.missing_tool:
            self.run.missing_tools.append(name)

    def review_hold(self) -> str | None:
        """Why the diff must not go to the AC reviewer: a secrets gate that ran and did not
        pass (it found something, or could not scan), or a file a gate changed again."""
        menu = self.ctx.cfg.gates
        for result in self.run.results:
            gate = menu.get(result.name)
            if gate is not None and gate.builtin is BuiltinGate.GITLEAKS:
                if result.status is not GateStatus.PASS:
                    return (
                        f"the {result.name} gate did not pass, so the diff is not sent to the LLM"
                    )
        moved = self.ctx.changed_during_gates()
        if moved:
            return f"{moved[0]} changed while the gates ran, so the diff is not sent to the LLM"
        return None


def run_gates(
    ctx: GateContext,
    *,
    reviewer: Reviewer | None = None,
    reviewer_unavailable: str = "no LLM is configured",
    only: str | None = None,
    override_ac: str | None = None,
    hold_prepare: str | None = None,
) -> GateRun:
    """Run `prepare` and the gates for one attempt; never stops at the first failure."""
    menu = ctx.cfg.gates
    named = set(ctx.task.gates)
    names = [only] if only is not None else gate_order([*menu, *named])
    attempt = _Attempt(ctx, reviewer, reviewer_unavailable, override_ac)
    if any(n in menu and menu[n].run is not None for n in names):
        prepare = None if hold_prepare else run_prepare(ctx)
        if hold_prepare and ctx.cfg.prepare is not None:
            attempt.run.results.append(_error("prepare", f"not run: {hold_prepare}", required=True))
            attempt.prepare_ok = False
            attempt.prepare_why = "the prepare step did not run"
        if prepare is not None:
            attempt.run.results.append(prepare.result)
            attempt.run.outputs["prepare"] = prepare.full_output
            attempt.prepare_ok = prepare.result.status is GateStatus.PASS
    paths = owned_paths(ctx.root, ctx.task, extra_protected=ctx.protected_extra())
    for name in names:
        gate = menu.get(name)
        if gate is None:
            message = f"{ctx.task.id} names {name}, which is not in the gate menu"
            attempt.run.results.append(_error(name, message, required=True))
        elif gate.run is not None:
            attempt.command(name, gate, paths, name in named or gate.required)
        else:
            attempt.builtin(name, gate, name in named or gate.required)
    return attempt.run
