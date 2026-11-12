"""Dispatch isolation fixes from the step 07 security reviews (SECURITY.md §9, §11).

- A script `claude` (npm: `#!/usr/bin/env node`) runs its interpreter from outside the
  repository and aipm's worktrees, even for `--version`.
- Putting files back after a minor violation never follows a link, whatever a process left
  behind in the agent-writable tree does meanwhile, and refuses `..`; an error blocks the task.
- A rebase whose result touches other paths than the verified commit counts as a conflict.
"""

import os
from pathlib import Path

import pytest

from aipm.adapters import claude_code
from aipm.adapters.claude_code import ClaudeCodeAdapter
from aipm.domain.errors import PolicyViolation
from aipm.execution import git
from aipm.execution.worktree import WorktreeManager, ensure_integration, integrate
from tests.conftest import run_git
from tests.integration.conftest import UserDirs
from tests.integration.conftest import user_dirs as user_dirs  # noqa: PLC0414 - the fixture


@pytest.fixture(autouse=True)
def fresh_cache() -> None:
    claude_code._detected.clear()  # pyright: ignore[reportPrivateUsage]


@pytest.fixture
def repo(tmp_repo: Path, user_dirs: UserDirs) -> Path:
    (user_dirs.home / ".gitconfig").write_text(
        "[user]\n\tname = aipm owner\n\temail = owner@example.invalid\n", encoding="utf-8"
    )
    return tmp_repo


def test_a_script_claude_runs_its_interpreter_from_outside_the_repository(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """An npm-installed `claude` is `#!/usr/bin/env node`: a `node` planted in the repository
    (an active `.venv/bin`) must never run, not even for `--version` (step 07 review)."""
    repo, outside = tmp_path / "repo", tmp_path / "tools"
    (repo / "bin").mkdir(parents=True)
    outside.mkdir()
    marker = tmp_path / "planted-ran"
    planted = repo / "bin" / "fakenode"
    planted.write_text(f"#!/bin/sh\ntouch '{marker}'\nexec /bin/sh \"$@\"\n")
    planted.chmod(0o755)
    real = outside / "fakenode"
    real.write_text('#!/bin/sh\nexec /bin/sh "$@"\n')
    real.chmod(0o755)
    claude = outside / "claude"
    claude.write_text(
        '#!/usr/bin/env fakenode\n[ "$1" = --version ] && echo "2.1.300 (Claude Code)"\nexit 0\n'
    )
    claude.chmod(0o755)
    monkeypatch.setenv("PATH", f"{repo / 'bin'}:{outside}:/usr/bin:/bin")
    caps = ClaudeCodeAdapter(which=lambda _n: str(claude)).detect(repo=repo)
    assert caps.version == "2.1.300"
    assert caps.launcher == (str(real), str(claude))
    assert not marker.exists()


def commit_file(repo: Path, path: str, text: str) -> str:
    (repo / path).parent.mkdir(parents=True, exist_ok=True)
    (repo / path).write_text(text, encoding="utf-8")
    run_git(repo, "add", "-A")
    run_git(repo, "commit", "-q", "-m", path)
    return git.head_sha(repo)


@pytest.mark.parametrize("path", ["../victim", "x/../../victim", "/etc/x", "a//b", "./a"])
def test_putting_files_back_refuses_paths_that_are_not_plain(repo: Path, path: str) -> None:
    with pytest.raises(PolicyViolation, match="not a plain path"):
        git.restore_paths(repo, git.head_sha(repo), [path])


def test_restoring_a_changed_file_cannot_be_raced_out_of_the_tree(
    repo: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    base = commit_file(repo, "x/config", "base\n")
    (repo / "x" / "config").write_text("agent\n", encoding="utf-8")
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "config").write_text("precious\n", encoding="utf-8")
    real_open = os.open
    swapped: list[bool] = []

    def racing_open(path: object, flags: int, *args: object, **kwargs: object) -> int:
        fd = real_open(path, flags, *args, **kwargs)  # type: ignore[arg-type]
        if path == "x" and not swapped:
            swapped.append(True)
            (repo / "x").rename(repo / "x-moved")
            (repo / "x").symlink_to(outside)
        return fd

    monkeypatch.setattr(git.os, "open", racing_open)
    git.restore_paths(repo, base, ["x/config"])
    assert swapped
    assert (outside / "config").read_text(encoding="utf-8") == "precious\n"
    assert (repo / "x-moved" / "config").read_text(encoding="utf-8") == "base\n"


def test_restoring_recreates_files_links_and_modes_as_the_base_has_them(repo: Path) -> None:
    (repo / "bin").mkdir()
    (repo / "bin" / "run").write_text("#!/bin/sh\n", encoding="utf-8")
    (repo / "bin" / "run").chmod(0o755)
    (repo / "here").symlink_to("README.md")
    base = commit_file(repo, "deep/a/b.txt", "b\n")
    run_git(repo, "rm", "-q", "-r", "deep", "bin", "here")
    git.restore_paths(repo, base, ["deep/a/b.txt", "bin/run", "here"])
    assert (repo / "deep" / "a" / "b.txt").read_text(encoding="utf-8") == "b\n"
    assert os.access(repo / "bin" / "run", os.X_OK)
    assert str((repo / "here").readlink()) == "README.md"
    assert run_git(repo, "status", "--porcelain") == ""


def test_a_revert_aipm_cannot_do_blocks_the_task(repo: Path) -> None:
    base = git.head_sha(repo)
    locked = repo / "locked"
    locked.mkdir()
    (locked / "x").write_text("x", encoding="utf-8")
    locked.chmod(0)
    try:
        with pytest.raises(PolicyViolation):
            git.restore_paths(repo, base, ["locked/x"])
    finally:
        locked.chmod(0o755)


def test_a_rebase_that_changes_other_paths_is_a_conflict(repo: Path, tmp_path: Path) -> None:
    """Rename detection could bring another task's file into the rebased commit; no gate saw it."""
    commit_file(repo, "shared/old.txt", "a\nb\nc\nd\ne\nf\n")
    base = ensure_integration(repo, "aipm/integration").head
    manager = WorktreeManager(repo, root=tmp_path / "wt")
    one, two = manager.create("T-001", base), manager.create("T-002", base)
    (one / "shared" / "old.txt").rename(one / "shared" / "new.txt")
    first = git.commit(one, ["shared/old.txt", "shared/new.txt"], message="t1", trailers=[])
    (two / "shared" / "old.txt").write_text("a\nb\nc\nd\ne\nf\ng\n", encoding="utf-8")
    second = git.commit(two, ["shared/old.txt"], message="t2", trailers=[])
    assert integrate(repo, one, "aipm/integration", first, base) == first
    assert integrate(repo, two, "aipm/integration", second, base) is None
    assert git.ref_sha(repo, "aipm/integration") == first
