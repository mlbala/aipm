"""What G3 shows about the plan itself (ARCHITECTURE §7.2, SECURITY.md §7.5).

The task table, the DAG depth and parallel width, every declared `deps_add`, and every task that
owns test or test-config paths. The command lines come from the trusted config through the trust
store's surface, never from the plan, so they are not built here.
"""

from collections.abc import Sequence
from dataclasses import dataclass

from aipm.domain.dag import dag_metrics, owned_test_or_config
from aipm.domain.models import Task


@dataclass(frozen=True, slots=True)
class PlanFacts:
    """The plan side of G3."""

    rows: tuple[str, ...]
    depth: int
    width: int
    deps_add: tuple[str, ...]
    test_or_config: tuple[str, ...]


def _flat(text: str) -> str:
    return " ".join(text.split())


def plan_facts(tasks: Sequence[Task], *, test_roots: Sequence[str]) -> PlanFacts:
    """Collect the G3 facts from validated tasks."""
    ordered = sorted(tasks, key=lambda t: t.id)
    depth, width = dag_metrics(ordered)
    rows = [f"{'ID':<6} {'type':<9} {'size':<4} {'after':<16} title"]
    for t in ordered:
        after = ",".join(t.depends_on) or "-"
        rows.append(f"{t.id:<6} {t.type.value:<9} {t.size.value:<4} {after:<16} {_flat(t.title)}")
    deps = [f"{t.id}: {d.ecosystem.value} {d.name}" for t in ordered for d in t.deps_add]
    owners = [
        f"{t.id}: {', '.join(hits)}"
        for t in ordered
        if (hits := owned_test_or_config(t, test_roots))
    ]
    return PlanFacts(tuple(rows), depth, width, tuple(deps), tuple(owners))
