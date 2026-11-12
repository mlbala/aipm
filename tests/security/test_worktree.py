"""Task worktrees and the integration branch (ARCHITECTURE §12.2, ADR-0008).

Worktrees live outside the repository; the integration branch is aipm's own, never one of the
user's; a task commit reaches it only as one commit on its head, by compare-and-swap.
"""

from pathlib import Path

import pytest

from aipm.domain.errors import PolicyViolation, UsageError
from aipm.execution import git
from aipm.execution.worktree import (
    WorktreeManager,
    check_integration_branch,
    ensure_integration,
    find_task_commit,
    integrate,
    task_branch,
)
from tests.conftest import run_git
from tests.integration.conftest import UserDirs, user_dirs  # noqa: F401 - an autouse fixture

INTEGRATION = "aipm/integration"
RUN = "r-20261112-1200-ab12"


@pytest.fixture
def repo(tmp_repo: Path, user_dirs: UserDirs) -> Path:  # noqa: F811 - the imported fixture
    (user_dirs.home / ".gitconfig").write_text(
        "[user]\n\tname = aipm owner\n\temail = owner@example.invalid\n", encoding="utf-8"
    )
    return tmp_repo


@pytest.fixture
def manager(repo: Path, tmp_path: Path) -> WorktreeManager:
    return WorktreeManager(repo, root=tmp_path / "cache" / "worktrees")


def task_commit(wt: Path, path: str, text: str, task: str, attempt: int = 1) -> str:
    (wt / path).parent.mkdir(parents=True, exist_ok=True)
    (wt / path).write_text(text, encoding="utf-8")
    trailers = [("Aipm-Task", task), ("Aipm-Run", RUN), ("Aipm-Attempt", str(attempt))]
    return git.commit(wt, [path], message=f"aipm: {task}", trailers=trailers)


@pytest.mark.parametrize("name", ["aipm/integration", "aipm/int-2", "aipm/x/y"])
def test_integration_branches_aipm_owns(name: str) -> None:
    assert check_integration_branch(name) == name


@pytest.mark.parametrize(
    "name", ["main", "master", "feature/x", "aipm", "aipm/task/T-001", "aipmx/a"]
)
def test_a_user_branch_is_never_the_integration_branch(name: str) -> None:
    with pytest.raises(PolicyViolation, match="not one of aipm's own branches"):
        check_integration_branch(name)


def test_a_malformed_integration_branch_is_a_usage_error() -> None:
    with pytest.raises(UsageError):
        check_integration_branch("aipm/../main")


def test_task_branches_need_task_ids() -> None:
    assert task_branch("T-007") == "aipm/task/T-007"
    with pytest.raises(UsageError):
        task_branch("T-7; rm")


def test_worktrees_live_outside_the_repository(repo: Path, tmp_path: Path) -> None:
    with pytest.raises(PolicyViolation, match="inside the repository"):
        WorktreeManager(repo, root=repo / "cache")
    default = WorktreeManager(repo)
    assert not str(default.root).startswith(str(repo))


def test_create_replaces_a_leftover_and_remove_cleans_up(
    manager: WorktreeManager, repo: Path
) -> None:
    head = git.head_sha(repo)
    wt = manager.create("T-001", head)
    (wt / "left-over.txt").write_text("x", encoding="utf-8")
    assert manager.create("T-001", head) == wt  # a crash left it behind
    assert not (wt / "left-over.txt").exists()
    other = manager.create("T-002", head)
    assert manager.others("T-001") == (other,)
    manager.remove("T-002")
    assert not other.exists()
    assert manager.others("T-001") == ()
    # A directory git no longer knows (its record pruned) is still removed.
    run_git(repo, "worktree", "remove", "--force", str(wt))
    wt.mkdir()
    (wt / "stray").write_text("x", encoding="utf-8")
    manager.remove("T-001")
    assert not wt.exists()


def test_a_link_in_place_of_a_worktree_is_unlinked_not_followed(
    manager: WorktreeManager, tmp_path: Path
) -> None:
    precious = tmp_path / "precious"
    precious.mkdir()
    (precious / "keep").write_text("k", encoding="utf-8")
    manager.root.mkdir(parents=True)
    manager.path("T-001").symlink_to(precious)
    manager.remove("T-001")
    assert (precious / "keep").exists()
    assert not manager.path("T-001").exists()


def test_others_when_nothing_exists(manager: WorktreeManager) -> None:
    assert manager.others("T-001") == ()


def test_the_integration_branch_is_created_then_caught_up(repo: Path) -> None:
    head = git.head_sha(repo)
    first = ensure_integration(repo, INTEGRATION)
    assert (first.head, first.created) == (head, True)
    assert git.ref_sha(repo, INTEGRATION) == head
    run_git(repo, "commit", "-q", "--allow-empty", "-m", "user work")
    newer = git.head_sha(repo)
    caught = ensure_integration(repo, INTEGRATION)
    assert (caught.head, caught.caught_up, caught.diverged) == (newer, True, False)
    same = ensure_integration(repo, INTEGRATION)
    assert (same.created, same.caught_up, same.diverged) == (False, False, False)


def test_an_integration_branch_ahead_of_head_is_kept(repo: Path, tmp_path: Path) -> None:
    head = git.head_sha(repo)
    ensure_integration(repo, INTEGRATION)
    wt = tmp_path / "wt"
    git.worktree_add(repo, wt, "aipm/task/T-001", head)
    ahead = task_commit(wt, "a.txt", "a\n", "T-001")
    git.update_ref(repo, INTEGRATION, ahead, head)
    state = ensure_integration(repo, INTEGRATION)
    assert (state.head, state.diverged) == (ahead, False)


def test_a_diverged_integration_branch_is_reported(repo: Path, tmp_path: Path) -> None:
    head = git.head_sha(repo)
    ensure_integration(repo, INTEGRATION)
    wt = tmp_path / "wt"
    git.worktree_add(repo, wt, "aipm/task/T-001", head)
    ahead = task_commit(wt, "a.txt", "a\n", "T-001")
    git.update_ref(repo, INTEGRATION, ahead, head)
    run_git(repo, "commit", "-q", "--allow-empty", "-m", "user work")
    state = ensure_integration(repo, INTEGRATION)
    assert (state.head, state.diverged) == (ahead, True)


def test_a_checked_out_integration_branch_is_refused(repo: Path) -> None:
    ensure_integration(repo, INTEGRATION)
    run_git(repo, "checkout", "-q", INTEGRATION)
    with pytest.raises(UsageError, match="checked out"):
        ensure_integration(repo, INTEGRATION)


def test_integrate_fast_forwards_then_rebases(manager: WorktreeManager, repo: Path) -> None:
    base = ensure_integration(repo, INTEGRATION).head
    one = manager.create("T-001", base)
    two = manager.create("T-002", base)
    first = task_commit(one, "a.txt", "a\n", "T-001")
    second = task_commit(two, "b.txt", "b\n", "T-002")
    assert integrate(repo, one, INTEGRATION, first, base) == first
    merged = integrate(repo, two, INTEGRATION, second, base)
    assert merged is not None
    assert merged != second  # rebased onto T-001's commit
    assert git.ref_sha(repo, INTEGRATION) == merged
    assert git.changed_paths(repo, first, merged) == ["b.txt"]
    assert find_task_commit(repo, INTEGRATION, task="T-002", run=RUN, since=base) == merged
    assert (
        find_task_commit(repo, INTEGRATION, task="T-002", run=RUN, since=base, attempt=1) == merged
    )
    assert find_task_commit(repo, INTEGRATION, task="T-002", run=RUN, since=base, attempt=2) is None
    assert find_task_commit(repo, INTEGRATION, task="T-003", run=RUN, since=base) is None
    assert (
        find_task_commit(repo, INTEGRATION, task="T-001", run="r-20261112-1200-0000", since=None)
        is None
    )


def test_integrate_reports_a_conflict(manager: WorktreeManager, repo: Path) -> None:
    base = ensure_integration(repo, INTEGRATION).head
    one = manager.create("T-001", base)
    two = manager.create("T-002", base)
    first = task_commit(one, "README.md", "one\n", "T-001")
    second = task_commit(two, "README.md", "two\n", "T-002")
    assert integrate(repo, one, INTEGRATION, first, base) == first
    assert integrate(repo, two, INTEGRATION, second, base) is None
    assert git.ref_sha(repo, INTEGRATION) == first


def test_integrate_refuses_more_than_one_commit(manager: WorktreeManager, repo: Path) -> None:
    base = ensure_integration(repo, INTEGRATION).head
    wt = manager.create("T-001", base)
    task_commit(wt, "a.txt", "a\n", "T-001")
    extra = task_commit(wt, "b.txt", "b\n", "T-001")
    with pytest.raises(PolicyViolation, match="not a single commit"):
        integrate(repo, wt, INTEGRATION, extra, base)
    assert git.ref_sha(repo, INTEGRATION) == base


def test_integrate_needs_the_branch(manager: WorktreeManager, repo: Path) -> None:
    head = git.head_sha(repo)
    wt = manager.create("T-001", head)
    with pytest.raises(UsageError, match="gone"):
        integrate(repo, wt, INTEGRATION, head, head)
    assert find_task_commit(repo, INTEGRATION, task="T-001", run=RUN, since=None) is None


def test_a_since_commit_not_on_the_branch_searches_the_whole_branch(
    manager: WorktreeManager, repo: Path
) -> None:
    base = ensure_integration(repo, INTEGRATION).head
    wt = manager.create("T-001", base)
    first = task_commit(wt, "a.txt", "a\n", "T-001")
    integrate(repo, wt, INTEGRATION, first, base)
    run_git(repo, "commit", "-q", "--allow-empty", "-m", "unrelated")
    elsewhere = git.head_sha(repo)
    assert find_task_commit(repo, INTEGRATION, task="T-001", run=RUN, since=elsewhere) == first
