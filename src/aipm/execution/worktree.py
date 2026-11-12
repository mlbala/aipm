"""Task worktrees outside the repository, and the integration branch (ARCHITECTURE §12.2,
ADR-0008).

Each task attempt runs in `<user_cache_dir>/aipm/worktrees/<repo-id>/<T-ID>`, on the branch
`aipm/task/<T-ID>`, checked out from the integration branch's HEAD. Keeping worktrees out of the
repository keeps agents away from its `.pm/`. A passing task's single commit is fast-forwarded
onto the integration branch, rebased first when the branch moved since the task started; a
conflict is reported, never resolved. Every ref update is a compare-and-swap.

The integration branch must be aipm's own: under `aipm/` and not a task branch, because a
repository's `.pm/config.yaml` can name it, and aipm never commits to the user's branches.
"""

import os
import shutil
from dataclasses import dataclass
from pathlib import Path

import platformdirs

from aipm.domain.errors import PolicyViolation, UsageError
from aipm.domain.ids import is_valid_id
from aipm.execution import git
from aipm.security.paths import is_within
from aipm.state.layout import repo_id

WORKTREES_DIR = "worktrees"
AGENT_HOMES_DIR = "agents"
TASK_BRANCH_PREFIX = "aipm/task/"
INTEGRATION_PREFIX = "aipm/"


def cache_root() -> Path:
    """`<user_cache_dir>/aipm`."""
    return Path(platformdirs.user_cache_dir("aipm", appauthor=False))


def task_branch(task_id: str) -> str:
    """`aipm/task/<T-ID>`."""
    if not is_valid_id("task", task_id):
        raise UsageError(f"not a task ID: {task_id!r}")
    return f"{TASK_BRANCH_PREFIX}{task_id}"


def check_integration_branch(name: str) -> str:
    """`name`, if it can be aipm's integration branch (exit 6 otherwise, exit 2 if malformed)."""
    git.check_branch(name)
    if not name.startswith(INTEGRATION_PREFIX) or name.startswith(TASK_BRANCH_PREFIX):
        raise PolicyViolation(
            f"the integration branch {name!r} is not one of aipm's own branches: it must start "
            f"with {INTEGRATION_PREFIX} and not with {TASK_BRANCH_PREFIX}",
            hint="aipm never commits to your branches. Set git.integration_branch to a name "
            "such as aipm/integration (a repository's .pm/config.yaml may have set it).",
        )
    return name


def outside_repo(path: Path, repo: Path, what: str) -> Path:
    """`path`, refused (exit 6) when it lies inside the repository."""
    if is_within(path, repo):
        raise PolicyViolation(
            f"{what} ({path}) would be inside the repository",
            hint="Check XDG_CACHE_HOME and HOME, which a repository .env loaded by a tool such "
            "as pipenv can set.",
        )
    return path


class WorktreeManager:
    """The task worktrees of one repository. `root` is a seam for tests."""

    def __init__(self, repo: Path, *, root: Path | None = None) -> None:
        self.repo = Path(os.path.realpath(repo))
        base = cache_root() / WORKTREES_DIR if root is None else root
        self.root = outside_repo(base / repo_id(self.repo), self.repo, "the worktree directory")

    def path(self, task_id: str) -> Path:
        """Where the worktree of `task_id` lives."""
        task_branch(task_id)
        return self.root / task_id

    def create(self, task_id: str, start: str) -> Path:
        """A fresh worktree for `task_id` on `aipm/task/<T-ID>` at commit `start`; anything left
        there by an earlier attempt (a crash, a resume) is removed first."""
        self.remove(task_id)
        self.root.mkdir(mode=0o700, parents=True, exist_ok=True)
        if self.root.is_symlink() or not self.root.is_dir():
            raise PolicyViolation(f"{self.root} must be a real directory, not a link")
        path = self.path(task_id)
        git.worktree_add(self.repo, path, task_branch(task_id), start)
        return path

    def remove(self, task_id: str) -> None:
        """Remove the worktree of `task_id`, whether or not git still knows it."""
        path = self.path(task_id)
        git.worktree_remove(self.repo, path)
        if path.is_symlink():
            path.unlink()
        elif path.exists():
            shutil.rmtree(path)

    def others(self, task_id: str) -> tuple[Path, ...]:
        """The other tasks' worktrees that exist now (an agent may not read them)."""
        if not self.root.is_dir():
            return ()
        own = self.path(task_id)
        return tuple(
            sorted(p for p in self.root.iterdir() if p != own and is_valid_id("task", p.name))
        )


@dataclass(frozen=True, slots=True)
class Integration:
    """The integration branch at the start of a build."""

    branch: str
    head: str
    created: bool = False
    caught_up: bool = False
    diverged: bool = False


def ensure_integration(repo: Path, branch: str) -> Integration:
    """Create the integration branch at HEAD, or bring it up to HEAD when it is an ancestor.

    It must not be checked out anywhere: aipm moves it with `update-ref`, which would leave a
    work tree that has it checked out out of step (exit 2).
    """
    check_integration_branch(branch)
    where = git.checked_out(repo, branch)
    if where:
        raise UsageError(
            f"the integration branch {branch} is checked out in {where[0]}",
            hint="Switch that work tree to another branch; aipm moves this one itself.",
        )
    head = git.head_sha(repo)
    current = git.ref_sha(repo, branch)
    if current is None:
        git.update_ref(repo, branch, head, None)
        return Integration(branch, head, created=True)
    if current != head and git.is_ancestor(repo, current, head):
        git.update_ref(repo, branch, head, current)
        return Integration(branch, head, caught_up=True)
    diverged = current != head and not git.is_ancestor(repo, head, current)
    return Integration(branch, current, diverged=diverged)


def integrate(repo: Path, wt: Path, branch: str, commit: str, base: str) -> str | None:
    """Fast-forward `branch` to the task's `commit` (made on `base` in `wt`); rebase it onto the
    branch's head first when the branch moved. Returns the commit now at the branch's head, or
    `None` after a conflict (aborted; the task is blocked with `merge_conflict`).

    The result must be a single commit whose parent is the branch's head, else exit 6: the
    agent never had write access to git, so anything else means the work tree was tampered with.
    """
    head = git.ref_sha(repo, branch)
    if head is None:
        raise UsageError(f"the integration branch {branch} is gone")
    if head != base:
        git.clean(wt)
        if not git.rebase_onto(wt, head, base):
            return None
        commit = git.head_sha(wt)
    found = git.trailer_commits(repo, commit, since=head, limit=2)
    if len(found) != 1 or found[0].parents != (head,):
        raise PolicyViolation(
            f"the task commit {commit[:12]} is not a single commit on {branch}",
            hint="The task's work tree was changed outside aipm. Review it before going on.",
        )
    git.update_ref(repo, branch, commit, head)
    return commit


def find_task_commit(
    repo: Path, branch: str, *, task: str, run: str, since: str | None, attempt: int | None = None
) -> str | None:
    """The commit on `branch` (after `since`) carrying `Aipm-Task: task` and `Aipm-Run: run`
    (and `Aipm-Attempt`, when given): a resumed run never commits a task twice (§12.6)."""
    head = git.ref_sha(repo, branch)
    if head is None:
        return None
    if since is not None and not git.is_ancestor(repo, since, head):
        since = None
    for found in git.trailer_commits(repo, head, since=since):
        if found.task == task and found.run == run and attempt in (None, found.attempt):
            return found.sha
    return None
