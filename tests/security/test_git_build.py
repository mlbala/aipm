"""The v0.3 git calls: branches, worktrees, reverts, rebase and ref updates (ARCHITECTURE §12.2).

Each runs hardened like every other git call; ref updates are compare-and-swap, so a branch that
moved under aipm is never overwritten; a repository merge driver is refused before a rebase can
run it.
"""

from pathlib import Path

import pytest

from aipm.domain.errors import PolicyViolation, UsageError
from aipm.execution import git
from tests.conftest import run_git
from tests.integration.conftest import UserDirs, user_dirs  # noqa: F401 - an autouse fixture


@pytest.fixture
def repo(tmp_repo: Path, user_dirs: UserDirs) -> Path:  # noqa: F811 - the imported fixture
    """`tmp_repo`, with a global git identity for aipm's own commits."""
    (user_dirs.home / ".gitconfig").write_text(
        "[user]\n\tname = aipm owner\n\temail = owner@example.invalid\n", encoding="utf-8"
    )
    return tmp_repo


def commit_file(repo: Path, path: str, text: str, message: str) -> str:
    target = repo / path
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(text, encoding="utf-8")
    run_git(repo, "add", "-A")
    run_git(repo, "commit", "-q", "-m", message)
    return git.head_sha(repo)


@pytest.mark.parametrize(
    "name", ["aipm/integration", "aipm/task/T-001", "main", "feature/x_1.2", "a" * 100]
)
def test_branch_names_aipm_accepts(name: str) -> None:
    assert git.check_branch(name) == name


@pytest.mark.parametrize(
    "name",
    ["", "-x", "a..b", "a//b", "a/.b", "a/-b", "x.lock", "a/b.lock", "a.", "a/", ".x", "a b",
     "a~1", "a^", "a:b", "a@{1}", "a\\b", "a" * 101, "é"],
)  # fmt: skip
def test_branch_names_aipm_refuses(name: str) -> None:
    with pytest.raises(UsageError):
        git.check_branch(name)


def test_ref_updates_are_compare_and_swap(repo: Path) -> None:
    first = git.head_sha(repo)
    second = commit_file(repo, "a.txt", "a\n", "second")
    assert git.ref_sha(repo, "aipm/integration") is None
    git.update_ref(repo, "aipm/integration", first, None)
    assert git.ref_sha(repo, "aipm/integration") == first
    with pytest.raises(UsageError, match="update-ref"):
        git.update_ref(repo, "aipm/integration", second, None)  # exists already
    with pytest.raises(UsageError, match="update-ref"):
        git.update_ref(repo, "aipm/integration", second, second)  # not where aipm left it
    git.update_ref(repo, "aipm/integration", second, first)
    assert git.ref_sha(repo, "aipm/integration") == second
    with pytest.raises(UsageError):
        git.delete_branch(repo, "aipm/integration", first)
    git.delete_branch(repo, "aipm/integration", second)
    assert git.ref_sha(repo, "aipm/integration") is None


def test_ref_updates_need_full_commit_ids(repo: Path) -> None:
    head = git.head_sha(repo)
    for bad in ("HEAD", head[:12], "main", "--all"):
        with pytest.raises(UsageError, match="full commit id"):
            git.update_ref(repo, "aipm/integration", bad, None)
        with pytest.raises(UsageError, match="full commit id"):
            git.is_ancestor(repo, bad, head)


def test_ancestry(repo: Path) -> None:
    first = git.head_sha(repo)
    second = commit_file(repo, "a.txt", "a\n", "second")
    assert git.is_ancestor(repo, first, second)
    assert git.is_ancestor(repo, second, second)
    assert not git.is_ancestor(repo, second, first)


def test_worktrees_are_added_listed_and_removed(repo: Path, tmp_path: Path) -> None:
    head = git.head_sha(repo)
    wt = tmp_path / "wt" / "T-001"
    git.worktree_add(repo, wt, "aipm/task/T-001", head)
    assert (wt / "README.md").exists()
    assert (wt / ".git").is_file()
    assert git.current_branch(wt) == "aipm/task/T-001"
    assert git.checked_out(repo, "aipm/task/T-001") == [str(wt.resolve())]
    assert git.checked_out(repo, "main") == [str(repo.resolve())]
    paths = [w.path for w in git.worktrees(repo)]
    assert paths == [str(repo.resolve()), str(wt.resolve())]
    git.worktree_remove(repo, wt)
    assert not wt.exists()
    assert git.checked_out(repo, "aipm/task/T-001") == []
    # The branch stays, and adding again resets it to the start commit.
    second = commit_file(repo, "b.txt", "b\n", "second")
    git.worktree_add(repo, wt, "aipm/task/T-001", second)
    assert git.ref_sha(repo, "aipm/task/T-001") == second


def test_removing_a_worktree_git_does_not_know_only_prunes(repo: Path, tmp_path: Path) -> None:
    git.worktree_remove(repo, tmp_path / "nowhere")


def test_detached_head_has_no_branch(repo: Path) -> None:
    run_git(repo, "checkout", "-q", "--detach")
    assert git.current_branch(repo) is None


def test_restore_paths_reverts_changes_and_removes_new_files(repo: Path, tmp_path: Path) -> None:
    base = commit_file(repo, "src/keep.py", "keep\n", "base")
    (repo / "src" / "keep.py").write_text("changed\n", encoding="utf-8")
    (repo / "README.md").unlink()
    (repo / "new.txt").write_text("new\n", encoding="utf-8")
    (repo / "newdir").mkdir()
    (repo / "newdir" / "x.txt").write_text("x\n", encoding="utf-8")
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "precious").write_text("p\n", encoding="utf-8")
    (repo / "link").symlink_to(outside)
    run_git(repo, "add", "new.txt")  # staged, too
    git.restore_paths(repo, base, ["src/keep.py", "README.md", "new.txt", "newdir/", "link"])
    assert (repo / "src" / "keep.py").read_text(encoding="utf-8") == "keep\n"
    assert (repo / "README.md").exists()
    assert not (repo / "new.txt").exists()
    assert not (repo / "newdir").exists()
    assert not (repo / "link").is_symlink()
    assert (outside / "precious").exists()  # the link was removed, not followed
    assert run_git(repo, "status", "--porcelain") == ""


def test_restore_paths_refuses_a_path_through_a_link_out(repo: Path, tmp_path: Path) -> None:
    base = git.head_sha(repo)
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "victim").write_text("v\n", encoding="utf-8")
    (repo / "out").symlink_to(outside)
    with pytest.raises(PolicyViolation, match="inside the work tree"):
        git.restore_paths(repo, base, ["out/victim"])
    assert (outside / "victim").exists()


def test_restore_nothing_is_a_no_op(repo: Path) -> None:
    git.restore_paths(repo, "not-even-a-sha", [])


def test_rebase_replays_a_task_commit_onto_the_integration_head(repo: Path, tmp_path: Path) -> None:
    base = git.head_sha(repo)
    wt = tmp_path / "wt"
    git.worktree_add(repo, wt, "aipm/task/T-002", base)
    (wt / "task.txt").write_text("task\n", encoding="utf-8")
    task_commit = git.commit(
        wt, ["task.txt"], message="aipm: T-002", trailers=[("Aipm-Task", "T-002")]
    )
    integration = commit_file(repo, "other.txt", "other\n", "another task")
    assert git.rebase_onto(wt, integration, base)
    rebased = git.head_sha(wt)
    assert rebased != task_commit
    assert git.trailer_commits(repo, rebased, since=integration)[0].parents == (integration,)
    assert git.changed_paths(repo, integration, rebased) == ["task.txt"]


def test_a_rebase_conflict_is_aborted(repo: Path, tmp_path: Path) -> None:
    base = git.head_sha(repo)
    wt = tmp_path / "wt"
    git.worktree_add(repo, wt, "aipm/task/T-002", base)
    (wt / "README.md").write_text("mine\n", encoding="utf-8")
    mine = git.commit(wt, ["README.md"], message="aipm: T-002", trailers=[])
    integration = commit_file(repo, "README.md", "theirs\n", "conflicting")
    assert not git.rebase_onto(wt, integration, base)
    assert git.head_sha(wt) == mine  # aborted: back where it was
    assert run_git(wt, "status", "--porcelain") == ""


def test_a_repository_merge_driver_is_refused_and_never_runs(repo: Path, tmp_path: Path) -> None:
    marker = tmp_path / "driver-ran"
    base = git.head_sha(repo)
    wt = tmp_path / "wt"
    git.worktree_add(repo, wt, "aipm/task/T-002", base)
    (wt / "README.md").write_text("mine\n", encoding="utf-8")
    git.commit(wt, ["README.md"], message="aipm: T-002", trailers=[])
    commit_file(repo, ".gitattributes", "* merge=probe\n", "attributes")
    integration = commit_file(repo, "README.md", "theirs\n", "conflicting")
    with (repo / ".git" / "config").open("a", encoding="utf-8") as handle:
        handle.write(f'[merge "probe"]\n\tdriver = touch {marker}\n')
    with pytest.raises(PolicyViolation, match=r"merge\.probe\.driver"):
        git.rebase_onto(wt, integration, base)
    assert not marker.exists()


def test_every_call_turns_off_signature_checks_submodules_and_rerere() -> None:
    env = git.GIT_ENV
    pairs = {
        env[f"GIT_CONFIG_KEY_{i}"]: env[f"GIT_CONFIG_VALUE_{i}"]
        for i in range(int(env["GIT_CONFIG_COUNT"]))
    }
    assert pairs["log.showSignature"] == "false"
    assert pairs["merge.verifySignatures"] == "false"
    assert pairs["submodule.recurse"] == "false"
    assert pairs["rerere.enabled"] == "false"
    assert pairs["rebase.autoStash"] == "false"
    assert pairs["rebase.updateRefs"] == "false"


def test_fast_forward_only(repo: Path) -> None:
    base = git.head_sha(repo)
    ahead = commit_file(repo, "a.txt", "a\n", "ahead")
    run_git(repo, "reset", "-q", "--hard", base)
    git.merge_ff_only(repo, ahead)
    assert git.head_sha(repo) == ahead
    run_git(repo, "reset", "-q", "--hard", base)
    diverged = commit_file(repo, "b.txt", "b\n", "diverged")
    with pytest.raises(UsageError, match="merge --ff-only"):
        git.merge_ff_only(repo, ahead)
    assert git.head_sha(repo) == diverged


def test_log_lines_are_capped(repo: Path) -> None:
    base = git.head_sha(repo)
    tip = base
    for n in range(5):
        tip = commit_file(repo, f"f{n}.txt", f"{n}\n", f"commit {n}")
    lines, more = git.log_oneline(repo, base, tip, limit=3)
    assert [line.split(" ", 1)[1] for line in lines] == ["commit 4", "commit 3", "commit 2"]
    assert more
    lines, more = git.log_oneline(repo, base, tip)
    assert len(lines) == 5
    assert not more


def test_trailer_commits_read_only_well_formed_trailers(repo: Path) -> None:
    base = git.head_sha(repo)
    (repo / "a.txt").write_text("a\n", encoding="utf-8")
    good = git.commit(
        repo,
        ["a.txt"],
        message="aipm: T-001 one",
        trailers=[
            ("Aipm-Task", "T-001"),
            ("Aipm-Run", "r-20261112-1200-ab12"),
            ("Aipm-Attempt", "2"),
        ],
    )
    (repo / "b.txt").write_text("b\n", encoding="utf-8")
    odd = git.commit(
        repo,
        ["b.txt"],
        message="not aipm",
        trailers=[("Aipm-Task", "T-1; rm -rf"), ("Aipm-Run", "today"), ("Aipm-Attempt", "0")],
    )
    plain = commit_file(repo, "c.txt", "c\n", "plain")
    found = git.trailer_commits(repo, plain, since=base)
    assert [c.sha for c in found] == [plain, odd, good]
    assert (found[2].task, found[2].run, found[2].attempt) == ("T-001", "r-20261112-1200-ab12", 2)
    assert found[2].parents == (base,)
    assert (found[1].task, found[1].run, found[1].attempt) == (None, None, None)
    assert (found[0].task, found[0].run, found[0].attempt) == (None, None, None)
    assert [c.sha for c in git.trailer_commits(repo, plain, limit=2)] == [plain, odd]
    assert len(git.trailer_commits(repo, plain)) == 4


def test_changed_paths_between_commits(repo: Path) -> None:
    base = git.head_sha(repo)
    (repo / "README.md").unlink()
    (repo / "dir").mkdir()
    (repo / "dir" / "new.txt").write_text("n\n", encoding="utf-8")
    run_git(repo, "add", "-A")
    run_git(repo, "commit", "-q", "-m", "change")
    assert git.changed_paths(repo, base, git.head_sha(repo)) == ["README.md", "dir/new.txt"]
    assert git.changed_paths(repo, base, base) == []


def test_clean_removes_untracked_and_ignored_files(repo: Path) -> None:
    commit_file(repo, ".gitignore", "build/\n", "ignore")
    (repo / "build").mkdir()
    (repo / "build" / "out.bin").write_text("x", encoding="utf-8")
    (repo / "loose.txt").write_text("x", encoding="utf-8")
    git.clean(repo)
    assert not (repo / "build").exists()
    assert not (repo / "loose.txt").exists()
    assert (repo / ".gitignore").exists()
