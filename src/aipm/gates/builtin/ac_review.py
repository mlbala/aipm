"""ac_review: the LLM AC reviewer, veto only (ADR-0007, ARCHITECTURE §13.3).

The criteria and the diff reach the reviewer as `Untrusted`. A `not_met` fails the gate, and
the veto stops `done` whether or not the gate is required, unless that criterion was overridden
with `verify --override-ac ID --reason` (recorded by the caller). `met` adds nothing; `unclear`
gives a warning. Reported prompt injection is passed back to the caller, which records it.
"""

import time
from collections.abc import Callable, Sequence
from dataclasses import dataclass

from aipm.domain.errors import AipmError
from aipm.domain.models import ChangeStatus, GateFinding, GateResult, GateStatus, Severity
from aipm.execution.git import diff_text
from aipm.gates.builtin import BuiltinOutcome, outcome
from aipm.gates.context import GateContext
from aipm.roles.ac_reviewer import ACReview, ACReviewInput, ReviewedCriterion, Verdict
from aipm.scanners.base import stage_files
from aipm.security.untrusted import Untrusted

NAME = "ac_review"
MAX_DIFF_BYTES = 49_152

type Reviewer = Callable[[ACReviewInput], ACReview]


@dataclass(frozen=True, slots=True)
class ReviewOutcome:
    """The gate outcome, the reviewer's injection report, and the criteria overridden."""

    gate: BuiltinOutcome
    injection: tuple[str, ...] = ()
    overridden: tuple[str, ...] = ()


def build_diff(ctx: GateContext) -> tuple[str, bool]:
    """The attempt's diff (T2): tracked changes from git, new untracked files added as text."""
    paths = [c.path for c in ctx.changes.files if not c.path.startswith(".pm/")]
    text, cut = diff_text(ctx.root, ctx.ws.base_sha, paths, max_bytes=MAX_DIFF_BYTES)
    added = [c.path for c in ctx.changes.files if c.status is ChangeStatus.ADDED
             and not c.path.startswith(".pm/") and f" b/{c.path}\n" not in text]  # fmt: skip
    if added and not cut:
        stage = stage_files(ctx.root, added, ctx.ws.temp_dir / "ac-review-new")
        for rel in stage.files:
            body = stage.root.joinpath(*rel.split("/")).read_text("utf-8", errors="replace")
            text += f"--- /dev/null\n+++ b/{rel}\n" + "".join(
                f"+{line}\n" for line in body.splitlines()
            )
            if len(text.encode("utf-8")) > MAX_DIFF_BYTES:
                return text.encode("utf-8")[:MAX_DIFF_BYTES].decode("utf-8", errors="ignore"), True
    return text, cut


def run(
    ctx: GateContext,
    reviewer: Reviewer | None,
    earlier: Sequence[GateResult],
    *,
    required: bool,
    override_ac: str | None = None,
    unavailable: str = "no LLM is configured",
) -> ReviewOutcome:
    """Ask the AC reviewer, and veto on `not_met`."""
    started = time.monotonic()
    if reviewer is None:
        status = GateStatus.ERROR if required else GateStatus.SKIPPED
        return ReviewOutcome(outcome(NAME, status, unavailable, required=required, started=started))
    diff, cut = build_diff(ctx)
    criteria = tuple(
        ReviewedCriterion(c.id, Untrusted(c.text, source=f"approved:tasks:{c.id}"))
        for c in ctx.task.acceptance
    )
    try:
        review = reviewer(
            ACReviewInput(
                task_id=ctx.task.id,
                criteria=criteria,
                diff=Untrusted(diff or "(no changes)", source="agent:diff"),
                diff_cut=cut,
                gates=tuple((g.name, g.status.value) for g in earlier),
            )
        )
    except AipmError as exc:
        status = GateStatus.ERROR if required else GateStatus.SKIPPED
        message = f"the AC reviewer did not answer: {exc.message}"
        return ReviewOutcome(outcome(NAME, status, message, required=required, started=started))
    findings: list[GateFinding] = []
    vetoes: list[str] = []
    overridden: list[str] = []
    unclear: list[str] = []
    for item in review.criteria:
        severity = Severity.HIGH if item.verdict is Verdict.NOT_MET else Severity.LOW
        message = f"{item.verdict.value}: {item.evidence}"[:500]
        findings.append(GateFinding(tool=NAME, rule=item.id, severity=severity, message=message))
        if item.verdict is Verdict.NOT_MET:
            (overridden if item.id == override_ac else vetoes).append(item.id)
        elif item.verdict is Verdict.UNCLEAR:
            unclear.append(item.id)
    if unclear:
        ctx.warnings.append(f"ac_review: unclear for {', '.join(unclear)}")
    if vetoes:
        gate = outcome(NAME, GateStatus.FAIL, f"not met: {', '.join(vetoes)}", required=required,
                       started=started, findings=findings)  # fmt: skip
    else:
        note = f" (overridden: {', '.join(overridden)})" if overridden else ""
        gate = outcome(NAME, GateStatus.PASS, f"no veto{note}", required=required,
                       started=started, findings=findings)  # fmt: skip
    return ReviewOutcome(gate, tuple(review.injection_suspected), tuple(overridden))
