"""Which done tasks this machine saw pass, recorded outside the repository (red-team v0.3).

`.pm/tasks.yaml` is committed, so a cloned repository can arrive with tasks marked `done` that
no gate on this machine ever passed (the v0.1 and v0.2 reviews' "back done with a local
record"). Each time aipm marks a task done (`build`, `run`, `verify`), it records the task's run
and commit in `<user_state_dir>/aipm/done/<repo-id>.json`. `status`, `status --task` and
`build --dry-run` show a done task without a matching record as claimed by the repository.
Nothing else changes: such a task still unlocks the tasks after it (the owner's choice).
"""

import json
from collections.abc import Iterable
from pathlib import Path

from aipm.domain.models import Done, Task, TaskStatus
from aipm.state.layout import repo_id
from aipm.state.private_files import read_private, state_dir, write_private

MAX_RECORD_BYTES = 1_048_576


def _path(repo: Path) -> Path:
    return state_dir(repo) / "done" / f"{repo_id(repo)}.json"


def _entry(done: Done) -> dict[str, str | None]:
    return {"run_id": done.run_id, "commit": done.commit}


def _load(repo: Path) -> dict[str, object]:
    data = read_private(_path(repo), limit=MAX_RECORD_BYTES)
    try:
        loaded: object = json.loads(data) if data else {}
    except ValueError:
        return {}
    return {str(k): v for k, v in loaded.items()} if isinstance(loaded, dict) else {}  # pyright: ignore[reportUnknownVariableType, reportUnknownMemberType, reportUnknownArgumentType]


def record_done(repo: Path, task_id: str, done: Done) -> None:
    """Record that aipm itself marked `task_id` done, with `done`'s run and commit."""
    records = _load(repo)
    records[task_id] = _entry(done)
    write_private(_path(repo), json.dumps(records, sort_keys=True).encode("ascii"))


def claimed(repo: Path, tasks: Iterable[Task]) -> list[str]:
    """The done tasks this machine has no record of finishing, in task-ID order."""
    records = _load(repo)
    return sorted(
        t.id
        for t in tasks
        if t.status is TaskStatus.DONE
        and t.done is not None
        and records.get(t.id) != _entry(t.done)
    )
