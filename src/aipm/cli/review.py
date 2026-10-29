"""G2 and G3 in the terminal (ARCHITECTURE §7.2, SECURITY.md §7.5).

Everything shown here can hold model or repository text, so every line goes through
`print_untrusted` (sanitized, no markup, no escapes). The command lines at G3 come from the
trusted config through the trust store's surface, printed in full. Prompts use `typer.confirm`
with aipm's own fixed questions.
"""

from collections.abc import Sequence

import typer

from aipm.app.approve import DesignReview, PlanReview
from aipm.cli.output import print_untrusted, warn

MAX_CHANGES_SHOWN = 50


def _section(title: str, lines: Sequence[str]) -> None:
    print_untrusted(f"{title}:")
    for line in lines or ("(none)",):
        print_untrusted(f"  - {line}")


def show_design(review: DesignReview) -> None:
    """G2: the stack, the components, the ADR titles and the threats of medium or higher."""
    print_untrusted("\nDesign (G2): .pm/architecture.md, .pm/threat-model.md, .pm/adr/")
    stack = ", ".join(review.stack) or "not specified"
    print_untrusted(f"Stack: {stack}; template {review.stack_template}")
    print_untrusted(f"LLM app: {'yes' if review.is_llm_app else 'no'}")
    _section("Components", review.components)
    _section("ADRs", review.adrs)
    _section("Threats (medium or higher)", review.threats)
    for problem in review.problems:
        print_untrusted(f"cannot approve: {problem}")


def show_plan(review: PlanReview, changes: Sequence[str] = ()) -> None:
    """G3: the task table, depth and width, every command line, every new dependency, and the
    tasks that own test or test-config paths."""
    facts = review.facts
    warn(review.warnings)  # before any question about trust (ARCHITECTURE §15)
    print_untrusted(f"\nPlan (G3): .pm/tasks.yaml (sha256 {review.sha256[:12]})")
    for row in facts.rows:
        print_untrusted(f"  {row}")
    print_untrusted(f"DAG depth {facts.depth}, widest level {facts.width} tasks")
    if changes:
        shown = list(changes[:MAX_CHANGES_SHOWN])
        if len(changes) > MAX_CHANGES_SHOWN:
            shown.append(f"... and {len(changes) - MAX_CHANGES_SHOWN} more")
        _section("Changes the plan validator made", shown)
    _section("New dependencies (deps_add)", facts.deps_add)
    _section("Tasks that own test or test-config paths", facts.test_or_config)
    print_untrusted("")
    if review.surface_error is not None:
        print_untrusted(f"The execution surface cannot be trusted: {review.surface_error}")
    for line in review.surface_lines:
        print_untrusted(line)
    print_untrusted(f"trusted: {'yes' if review.trusted else 'no'}")
    for problem in review.problems:
        print_untrusted(f"cannot approve: {problem}")


def confirm_risk(role: str, excerpts: Sequence[str]) -> bool:
    """Warn about suspected prompt injection and ask whether to continue."""
    print_untrusted(
        f"\nwarning: the {role} found what look like instructions hidden in its input:", err=True
    )
    for excerpt in excerpts:
        print_untrusted(f"  > {excerpt}", err=True)
    print_untrusted("aipm ignores them, but review the input before you rely on the result.",
                    err=True)  # fmt: skip
    return typer.confirm("Continue anyway?", default=False)


def ask_design() -> bool:
    """The G2 question."""
    return typer.confirm("Approve the design (G2)?", default=False)


def ask_plan(review: PlanReview) -> bool:
    """The G3 question; an interactive yes also trusts the surface shown above."""
    if review.trusted:
        return typer.confirm("Approve the plan (G3)?", default=False)
    return typer.confirm(
        "Approve the plan (G3) and trust these exact commands for this repository?", default=False
    )


class ReviewPrompter:
    """`DesignPrompter` and `PlanPrompter` for a real terminal."""

    def confirm_risk(self, role: str, excerpts: Sequence[str]) -> bool:
        """Warn about suspected prompt injection; True continues."""
        return confirm_risk(role, excerpts)

    def approve_design(self, review: DesignReview) -> bool:
        """Show G2 and ask."""
        show_design(review)
        return ask_design()

    def approve_plan(self, review: PlanReview, changes: Sequence[str]) -> bool:
        """Show G3 and ask."""
        show_plan(review, changes)
        if review.surface_hash is None:
            return False
        return ask_plan(review)
