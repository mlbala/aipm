"""Bare `aipm`: the phase report and the next step (ARCHITECTURE §7.3).

Read-only and LLM-free. The CLI prints the report and, in an interactive terminal, offers to run
`next_command`, which is always one of aipm's own commands (plus a validated task ID).
"""

from dataclasses import dataclass
from pathlib import Path

from aipm.app import runtime
from aipm.app.snapshot import load_state
from aipm.app.workspace import find_repo_root
from aipm.domain.phase import PhaseReport, derive_phase


@dataclass(frozen=True, slots=True)
class PhaseView:
    """The phase report for one repository."""

    repo_root: str
    report: PhaseReport
    warnings: tuple[str, ...] = ()

    @property
    def lines(self) -> tuple[str, ...]:
        """The report as printed."""
        r = self.report
        lines = [f"Phase: {r.phase.value}"]
        lines.extend(f"stale: {impact}" for impact in r.impacts)
        lines.extend(f"blocked: {blocker}" for blocker in r.blockers)
        lines.append(f"Next: {r.next_command or 'nothing; the plan is built'}")
        return tuple(lines)

    def to_data(self) -> dict[str, object]:
        """The `--json` payload."""
        return {"repo": self.repo_root, **self.report.to_data()}


def run(project: Path | None) -> PhaseView:
    """Derive the phase of the repository at (or above) `project`."""
    root = find_repo_root(project)
    state = load_state(runtime.open_repo_store(root))
    return PhaseView(str(root), derive_phase(state.snapshot), state.warnings)
