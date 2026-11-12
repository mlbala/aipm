"""Pure scheduler: ready set, disjoint-ownership batching, serialized resources (§12.3).

- **Ready:** a task is ready when it is `todo` (or was started by the interrupted run being
  resumed) and every dependency is `done` or `skipped`.
- **Batching:** a batch holds at most `slots` ready tasks, in task-ID order, such that no two
  of them (nor any task already running) conflict.
- **Conflict:** two tasks conflict when an owned glob of one may match a path the other owns
  (`dag.globs_may_overlap`, conservative), or both touch the same serialized resource: a path
  in `plan.serialized_paths`, or the lockfile of an ecosystem both add a dependency in. The
  plan validator lets serialized paths overlap and leaves them to this scheduler (§9).
"""

from collections.abc import Collection, Iterable, Mapping, Sequence

from aipm.domain.dag import fold_path, globs_may_overlap, is_serialized
from aipm.domain.models import Task, TaskStatus

FINISHED = frozenset({TaskStatus.DONE, TaskStatus.SKIPPED})


def ready(
    tasks: Iterable[Task],
    *,
    resumable: Collection[str] = (),
    only: Collection[str] | None = None,
    statuses: Mapping[str, TaskStatus] | None = None,
) -> list[Task]:
    """The tasks that may start now, in task-ID order.

    `resumable` names `in_progress` tasks that the run being resumed started; `only` limits the
    result (`--only`); `statuses` overrides task statuses (a dry run's simulation).
    """
    listed = list(tasks)
    status = {t.id: t.status for t in listed}
    status.update(statuses or {})
    found: list[Task] = []
    for task in sorted(listed, key=lambda t: t.id):
        if only is not None and task.id not in only:
            continue
        own = status[task.id]
        startable = own is TaskStatus.TODO or (
            own is TaskStatus.IN_PROGRESS and task.id in resumable
        )
        if startable and all(status.get(dep) in FINISHED for dep in task.depends_on):
            found.append(task)
    return found


def resources(task: Task, serialized: Sequence[str]) -> frozenset[str]:
    """The serialized resources `task` touches."""
    patterns = tuple(serialized)
    owned = {f"path:{fold_path(g)}" for g in task.owns_files if is_serialized(g, patterns)}
    locks = {f"lockfile:{d.ecosystem.value}" for d in task.deps_add}
    return frozenset(owned | locks)


def conflict(a: Task, b: Task, serialized: Sequence[str]) -> bool:
    """Whether `a` and `b` may not run at the same time."""
    if resources(a, serialized) & resources(b, serialized):
        return True
    return any(globs_may_overlap(ga, gb) for ga in a.owns_files for gb in b.owns_files)


def next_batch(
    candidates: Iterable[Task],
    *,
    running: Iterable[Task] = (),
    slots: int,
    serialized: Sequence[str],
) -> list[Task]:
    """At most `slots` candidates, in task-ID order, that conflict with no running task and
    with no other task chosen."""
    chosen: list[Task] = []
    busy = list(running)
    for task in sorted(candidates, key=lambda t: t.id):
        if len(chosen) >= slots:
            break
        if any(conflict(task, other, serialized) for other in busy):
            continue
        chosen.append(task)
        busy.append(task)
    return chosen


def waves(
    tasks: Iterable[Task],
    *,
    parallel: int,
    serialized: Sequence[str],
    only: Collection[str] | None = None,
) -> list[list[str]]:
    """The batches a build would run if every task passed (`build --dry-run`)."""
    listed = list(tasks)
    statuses: dict[str, TaskStatus] = {}
    batches: list[list[str]] = []
    while True:
        candidates = ready(listed, only=only, statuses=statuses)
        batch = next_batch(candidates, slots=parallel, serialized=serialized)
        if not batch:
            return batches
        batches.append([t.id for t in batch])
        statuses.update({t.id: TaskStatus.DONE for t in batch})
