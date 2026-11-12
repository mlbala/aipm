"""Property: no batch the scheduler builds holds two tasks that may not run together."""

from hypothesis import given
from hypothesis import strategies as st

from aipm.domain.models import (
    AcceptanceCriterion,
    DependencyAdd,
    Ecosystem,
    Task,
    TaskSize,
    TaskType,
)
from aipm.domain.scheduler import conflict, next_batch

SERIALIZED = ("pyproject.toml", "uv.lock", "*lock*", "migrations/**")
GLOB = st.sampled_from(
    [
        "src/**", "src/app/**", "src/app/api.py", "src/app/*.py", "src/db/**", "src/*.py",
        "tests/**", "tests/test_api.py", "tests/app/**", "docs/**", "docs/guide.md",
        "uv.lock", "pyproject.toml", "migrations/**", "migrations/0001.sql", "app/x.py",
    ]
)  # fmt: skip


@st.composite
def tasks(draw: st.DrawFn) -> list[Task]:
    count = draw(st.integers(min_value=1, max_value=10))
    found: list[Task] = []
    for n in range(1, count + 1):
        owns = draw(st.lists(GLOB, min_size=1, max_size=3, unique=True))
        adds = draw(st.lists(st.sampled_from(["httpx", "slowapi"]), max_size=1))
        found.append(
            Task(
                id=f"T-{n:03d}", title="t", type=TaskType.FEATURE, size=TaskSize.S,
                owns_files=owns,
                deps_add=[DependencyAdd(ecosystem=Ecosystem.PYPI, name=a) for a in adds],
                acceptance=[AcceptanceCriterion(id=f"AC-T{n:03d}-1", text="x")],
            )
        )  # fmt: skip
    return found


@given(tasks(), st.integers(min_value=1, max_value=8), st.data())
def test_no_batch_holds_a_conflicting_pair(
    found: list[Task], slots: int, data: st.DataObject
) -> None:
    running = data.draw(st.lists(st.sampled_from(found), max_size=2, unique_by=lambda t: t.id))
    candidates = [t for t in found if t not in running]
    batch = next_batch(candidates, running=running, slots=slots, serialized=SERIALIZED)
    assert len(batch) <= slots
    assert [t.id for t in batch] == sorted(t.id for t in batch)
    for i, a in enumerate(batch):
        for b in [*batch[i + 1 :], *running]:
            assert not conflict(a, b, SERIALIZED)
    # Deterministic: the same input gives the same batch.
    again = next_batch(
        list(reversed(candidates)), running=running, slots=slots, serialized=SERIALIZED
    )
    assert batch == again
