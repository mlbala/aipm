"""The pure scheduler (ARCHITECTURE §12.3): ready set, disjoint batches, serialized resources."""

from collections.abc import Sequence
from datetime import UTC, datetime

from aipm.domain.models import (
    AcceptanceCriterion,
    Blocked,
    BlockedReason,
    DependencyAdd,
    Done,
    Ecosystem,
    Task,
    TaskSize,
    TaskStatus,
    TaskType,
)
from aipm.domain.scheduler import conflict, next_batch, ready, resources, waves

SERIALIZED = ("pyproject.toml", "uv.lock", "package.json", "*lock*", "migrations/**")


def task(
    n: int,
    owns: Sequence[str] = (),
    *,
    deps: Sequence[int] = (),
    status: TaskStatus = TaskStatus.TODO,
    adds: Sequence[str] = (),
) -> Task:
    done = (
        Done(commit=None, run_id=None, at=datetime.now(UTC)) if status is TaskStatus.DONE else None
    )
    blocked = Blocked(reason=BlockedReason.GATES_FAILED) if status is TaskStatus.BLOCKED else None
    return Task(
        id=f"T-{n:03d}", title=f"Task {n}", type=TaskType.FEATURE, size=TaskSize.S,
        depends_on=[f"T-{d:03d}" for d in deps], status=status,
        owns_files=list(owns or [f"src/t{n}/**"]),
        deps_add=[DependencyAdd(ecosystem=Ecosystem.PYPI, name=name) for name in adds],
        acceptance=[AcceptanceCriterion(id=f"AC-T{n:03d}-1", text="works")],
        done=done, blocked=blocked,
    )  # fmt: skip


def ids(tasks: Sequence[Task]) -> list[str]:
    return [t.id for t in tasks]


def test_ready_needs_todo_and_finished_dependencies() -> None:
    tasks = [
        task(1, status=TaskStatus.DONE),
        task(2, deps=[1]),
        task(3, deps=[2]),
        task(4, status=TaskStatus.SKIPPED),
        task(5, deps=[4]),
        task(6, status=TaskStatus.BLOCKED),
        task(7, deps=[6]),
        task(8, status=TaskStatus.IN_PROGRESS),
        task(9, deps=[99]),  # unknown dependency: never ready
    ]
    assert ids(ready(tasks)) == ["T-002", "T-005"]
    assert ids(ready(tasks, resumable={"T-008"})) == ["T-002", "T-005", "T-008"]
    assert ids(ready(tasks, only={"T-005", "T-003"})) == ["T-005"]


def test_ready_is_in_task_id_order_whatever_the_input_order() -> None:
    assert ids(ready([task(3), task(1), task(2)])) == ["T-001", "T-002", "T-003"]


def test_overlapping_tasks_never_share_a_batch() -> None:
    a = task(1, ["src/app/**"])
    b = task(2, ["src/app/api.py"])
    c = task(3, ["docs/**"])
    assert conflict(a, b, SERIALIZED)
    assert not conflict(a, c, SERIALIZED)
    assert ids(next_batch([b, a, c], slots=3, serialized=SERIALIZED)) == ["T-001", "T-003"]


def test_a_running_task_blocks_what_overlaps_it() -> None:
    running = [task(1, ["src/app/**"])]
    candidates = [task(2, ["src/app/x.py"]), task(3, ["docs/**"])]
    assert ids(next_batch(candidates, running=running, slots=2, serialized=SERIALIZED)) == ["T-003"]


def test_serialized_paths_and_lockfiles_are_one_task_at_a_time() -> None:
    lock_a = task(1, ["src/a/**", "uv.lock"])
    lock_b = task(2, ["src/b/**", "uv.lock"])
    dep_a = task(3, ["src/c/**"], adds=["slowapi"])
    dep_b = task(4, ["src/d/**"], adds=["httpx"])
    plain = task(5, ["src/e/**"])
    assert resources(lock_a, SERIALIZED) == frozenset({"path:uv.lock"})
    assert resources(dep_a, SERIALIZED) == frozenset({"lockfile:pypi"})
    assert resources(plain, SERIALIZED) == frozenset()
    assert conflict(lock_a, lock_b, SERIALIZED)
    assert conflict(dep_a, dep_b, SERIALIZED)
    batch = next_batch([lock_a, lock_b, dep_a, dep_b, plain], slots=8, serialized=SERIALIZED)
    assert ids(batch) == ["T-001", "T-003", "T-005"]


def test_the_batch_is_capped_at_the_free_slots() -> None:
    tasks = [task(n) for n in range(1, 6)]
    assert ids(next_batch(tasks, slots=2, serialized=SERIALIZED)) == ["T-001", "T-002"]
    assert next_batch(tasks, slots=0, serialized=SERIALIZED) == []


def test_waves_simulate_a_build_where_every_task_passes() -> None:
    tasks = [
        task(1),
        task(2, deps=[1]),
        task(3, deps=[1]),
        task(4, deps=[1]),
        task(5, deps=[2, 3]),
        task(6, ["src/t2/x.py"], deps=[1]),  # overlaps T-002
    ]
    assert waves(tasks, parallel=2, serialized=SERIALIZED) == [
        ["T-001"],
        ["T-002", "T-003"],
        ["T-004", "T-005"],
        ["T-006"],
    ]
    assert waves(tasks, parallel=8, serialized=SERIALIZED, only={"T-001", "T-002"}) == [
        ["T-001"],
        ["T-002"],
    ]
    assert waves([task(1, deps=[2]), task(2, deps=[1])], parallel=4, serialized=()) == []
