"""Attempt snapshots and the `.pm/` write ledger, outside the repository (ADR-0021).

In manual mode the user's own agent works in the user's own tree, so `verify` cannot tell an
agent's edit from the state the tree was in when the task started, or from aipm's own `.pm/`
writes, by diffing `base_sha` alone. Two private files answer that:

- The **attempt snapshot**, taken by the first `aipm prompt` of a task (ARCHITECTURE §12.4 step
  1): hashes of git's and the agents' configuration (`integrity`), and of every file that
  differed from `base_sha` or was not tracked at that moment (`files`).
- The **write ledger**: the sha256 of every `.pm/` file aipm wrote last, per repository. A
  `.pm/` change whose hash is not the ledger's was made by someone else.

Both are T1 for aipm: an agent in the repository cannot reach them. They are still validated.
"""

import json
from datetime import UTC, datetime
from pathlib import Path
from typing import Annotated, Literal

from pydantic import AwareDatetime, Field, StringConstraints, ValidationError

from aipm.domain.errors import PolicyViolation, UsageError
from aipm.domain.ids import is_valid_id
from aipm.domain.models import RepoId, StrictModel
from aipm.domain.models.base import GitSha, Sha256, TaskId
from aipm.state.layout import repo_id
from aipm.state.private_files import read_private, remove_private, state_dir, write_private

MAX_SNAPSHOT_FILES = 20_000
MAX_SNAPSHOT_BYTES = 16 * 1_048_576
MAX_LEDGER_FILES = 20_000
MAX_LEDGER_BYTES = 8 * 1_048_576

SnapshotPath = Annotated[str, StringConstraints(min_length=1, max_length=4096)]
Label = Annotated[str, StringConstraints(min_length=1, max_length=4200)]


class AttemptSnapshot(StrictModel):
    """What the tree looked like when a task started (ARCHITECTURE §12.4 step 1)."""

    schema_version: Literal[1] = 1
    repo: RepoId
    task: TaskId
    base_sha: GitSha
    created_at: AwareDatetime
    integrity: dict[Label, Sha256 | None] = Field(default_factory=dict[str, str | None])
    files: dict[SnapshotPath, Sha256] = Field(
        default_factory=dict[str, str], max_length=MAX_SNAPSHOT_FILES
    )


class LedgerDoc(StrictModel):
    """aipm's last write to each `.pm/` file: its sha256, or `None` once aipm removed it."""

    schema_version: Literal[1] = 1
    files: dict[SnapshotPath, Sha256 | None] = Field(
        default_factory=dict[str, str | None], max_length=MAX_LEDGER_FILES
    )


def _snapshot_path(repo_root: Path, task_id: str) -> Path:
    if not is_valid_id("task", task_id):
        raise UsageError(f"{task_id!r} is not a task ID")
    return state_dir(repo_root) / "attempts" / repo_id(repo_root) / f"{task_id}.json"


def save_snapshot(repo_root: Path, snapshot: AttemptSnapshot) -> Path:
    """Write a task's attempt snapshot (0600, atomic); returns where."""
    path = _snapshot_path(repo_root, snapshot.task)
    write_private(path, snapshot.model_dump_json().encode("utf-8"))
    return path


def load_snapshot(repo_root: Path, task_id: str) -> AttemptSnapshot | None:
    """A task's attempt snapshot, or `None` if the task has none. A damaged one exits 6."""
    path = _snapshot_path(repo_root, task_id)
    data = read_private(path, limit=MAX_SNAPSHOT_BYTES)
    if data is None:
        return None
    try:
        snapshot = AttemptSnapshot.model_validate_json(data)
    except ValidationError:
        raise PolicyViolation(
            f"the attempt snapshot of {task_id} is damaged",
            hint=f"Start the task again: `aipm task reset {task_id}`, then `aipm prompt "
            f"{task_id}`.",
        ) from None
    if snapshot.task != task_id or snapshot.repo != repo_id(repo_root):
        raise PolicyViolation(f"the attempt snapshot of {task_id} belongs to another task")
    return snapshot


def delete_snapshot(repo_root: Path, task_id: str) -> bool:
    """Remove a task's attempt snapshot; returns whether there was one."""
    return remove_private(_snapshot_path(repo_root, task_id))


def new_snapshot(
    repo_root: Path,
    task_id: str,
    base_sha: str,
    *,
    integrity: dict[str, str | None],
    files: dict[str, str],
) -> AttemptSnapshot:
    """Build a snapshot for `task_id` taken now."""
    return AttemptSnapshot(
        repo=repo_id(repo_root),
        task=task_id,
        base_sha=base_sha,
        created_at=datetime.now(UTC),
        integrity=integrity,
        files=files,
    )


class WriteLedger:
    """The sha256 of aipm's last write to each `.pm/` file of one repository."""

    def __init__(self, repo_root: Path) -> None:
        self.path = state_dir(repo_root) / "ledger" / f"{repo_id(repo_root)}.json"

    def load(self) -> dict[str, str | None]:
        """Every recorded `.pm/` path and its hash; a damaged ledger exits 6."""
        data = read_private(self.path, limit=MAX_LEDGER_BYTES)
        if data is None:
            return {}
        try:
            return dict(LedgerDoc.model_validate_json(data).files)
        except ValidationError:
            raise PolicyViolation(
                f"the .pm/ write ledger {self.path} is damaged",
                hint="Remove it; the next verify then counts every .pm/ change as foreign.",
            ) from None

    def record(self, relpath: str, sha256: str | None) -> None:
        """Record aipm's write (or removal, `None`) of `.pm/<...>`."""
        files = self.load()
        files.pop(relpath, None)
        files[relpath] = sha256
        while len(files) > MAX_LEDGER_FILES:
            files.pop(next(iter(files)))
        doc = LedgerDoc(files=files)
        write_private(self.path, json.dumps(doc.model_dump(mode="json")).encode("utf-8"))
