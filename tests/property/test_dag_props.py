"""Properties of the plan validator (build prompt 04).

For any plan the validator accepts, the dependency graph is acyclic, and any two tasks with no
dependency path between them, which the scheduler could therefore run in the same batch, own no
common concrete path, unless both globs are serialized resources (ARCHITECTURE §9 rules 3-4).

Ownership is checked against a concrete universe of paths with a matcher written here, not
with the validator's own overlap test, so the property does not assume what it checks.
"""

import graphlib
import itertools
from fnmatch import fnmatchcase
from typing import Any

from hypothesis import HealthCheck, given, settings
from hypothesis import strategies as st

from aipm.domain.dag import PlanRules, validate_plan
from aipm.domain.models import ProposedTask, Task

DIRS = ["src", "lib", "docs"]
SUBDIRS = ["a", "b"]
FILES = ["x.py", "y.py", "uv.lock"]
SERIALIZED = ("uv.lock", "*lock*", "lib/a/x.py")
MENU = ("lint", "unit", "ac_trace")

UNIVERSE = [
    *FILES,
    *(f"{d}/{f}" for d in DIRS for f in FILES),
    *(f"{d}/{s}/{f}" for d in DIRS for s in SUBDIRS for f in FILES),
]

GLOB_PARTS = st.lists(
    st.sampled_from([*DIRS, *SUBDIRS, *FILES, "*", "*.py", "?.py", "**"]), min_size=1, max_size=3
)


def _matches(parts: list[str], pattern: list[str]) -> bool:
    if not pattern:
        return not parts
    if pattern[0] == "**":
        return any(_matches(parts[k:], pattern[1:]) for k in range(len(parts) + 1))
    return bool(parts) and fnmatchcase(parts[0], pattern[0]) and _matches(parts[1:], pattern[1:])


def matches(path: str, glob: str) -> bool:
    """A glob matches a path, or a directory above it (a literal glob may be a directory)."""
    parts, pattern = path.split("/"), glob.split("/")
    return any(_matches(parts[: k + 1], pattern) for k in range(len(parts)))


def serialized(glob: str) -> bool:
    return glob in SERIALIZED or (
        "*" not in glob and "?" not in glob and any(matches(glob, s) for s in SERIALIZED)
    )


@st.composite
def plans(draw: st.DrawFn) -> list[ProposedTask]:
    count = draw(st.integers(min_value=1, max_value=8))
    tasks: list[ProposedTask] = []
    for n in range(1, count + 1):
        globs = draw(st.lists(GLOB_PARTS.map("/".join), min_size=1, max_size=3))
        depends = draw(st.lists(st.integers(min_value=1, max_value=max(1, n - 1)), max_size=2))
        data: dict[str, Any] = {
            "id": f"T-{n:03d}",
            "title": f"Task {n}",
            "description": "",
            "type": "feature",
            "traces": [],
            "depends_on": [f"T-{d:03d}" for d in depends if d < n],
            "owns_files": globs,
            "reads_files": [],
            "deps_add": [],
            "acceptance": draw(st.lists(st.just("works"), min_size=1, max_size=4)),
            "gates": ["lint"],
            "size": draw(st.sampled_from(["S", "M", "L"])),
        }
        tasks.append(ProposedTask.model_validate(data))
    return draw(st.permutations(tasks))


def reachable(tasks: tuple[Task, ...]) -> dict[str, set[str]]:
    graph = {t.id: set(t.depends_on) for t in tasks}
    order = list(graphlib.TopologicalSorter(graph).static_order())
    reach: dict[str, set[str]] = {}
    for tid in order:
        reach[tid] = set(graph[tid])
        for dep in graph[tid]:
            reach[tid] |= reach[dep]
    return reach


@settings(max_examples=300, deadline=None, suppress_health_check=[HealthCheck.too_slow])
@given(plans())
def test_accepted_plans_are_acyclic_and_parallel_tasks_are_disjoint(
    proposed: list[ProposedTask],
) -> None:
    result = validate_plan(proposed, PlanRules(gate_menu=MENU, serialized_paths=SERIALIZED))
    if not result.ok:
        return
    ids = {t.id for t in result.tasks}
    assert all(d in ids for t in result.tasks for d in t.depends_on)
    reach = reachable(result.tasks)  # raises CycleError on a cycle
    for a, b in itertools.combinations(result.tasks, 2):
        if a.id in reach[b.id] or b.id in reach[a.id]:
            continue
        for path in UNIVERSE:
            for ga in (g for g in a.owns_files if matches(path, g)):
                for gb in (g for g in b.owns_files if matches(path, g)):
                    assert serialized(ga) and serialized(gb), (
                        f"{a.id} ({ga}) and {b.id} ({gb}) both own {path} and may run together"
                    )


@settings(max_examples=200, deadline=None)
@given(plans())
def test_every_accepted_task_respects_the_size_caps(proposed: list[ProposedTask]) -> None:
    result = validate_plan(proposed, PlanRules(gate_menu=MENU, serialized_paths=SERIALIZED))
    for task in result.tasks:
        assert len(task.owns_files) <= 40
        assert len(task.acceptance) <= 10
        assert not (task.size.value == "L" and len(task.acceptance) > 6)
        assert len(task.depends_on) <= 20
        assert set(task.gates) <= set(MENU)
