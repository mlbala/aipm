""".githooks/pre-push refuses every push the owner-only workflow forbids (AGENTS.md "Git").

Each test feeds the hook the ref lines git would send, in a temporary repository whose owner
identity comes from GIT_CONFIG_* variables (no user or system config is read).
"""

import os
import subprocess
from pathlib import Path

import pytest

from tests.conftest import REPO_ROOT

HOOK = REPO_ROOT / ".githooks" / "pre-push"
ZERO = "0" * 40
OWNER = ("Owner", "owner@example.invalid")


class Repo:
    def __init__(self, root: Path) -> None:
        self.root = root
        self.env = {
            "PATH": os.environ.get("PATH", ""),
            "HOME": str(root),
            "GIT_CONFIG_GLOBAL": os.devnull,
            "GIT_CONFIG_NOSYSTEM": "1",
            "GIT_CONFIG_COUNT": "3",
            "GIT_CONFIG_KEY_0": "user.name",
            "GIT_CONFIG_VALUE_0": OWNER[0],
            "GIT_CONFIG_KEY_1": "user.email",
            "GIT_CONFIG_VALUE_1": OWNER[1],
            "GIT_CONFIG_KEY_2": "core.hooksPath",
            "GIT_CONFIG_VALUE_2": os.devnull,
        }
        self.git("init", "-q", "-b", "main")

    def git(self, *args: str, env: dict[str, str] | None = None) -> str:
        proc = subprocess.run(
            ["git", *args],
            cwd=self.root,
            env={**self.env, **(env or {})},
            capture_output=True,
            text=True,
            check=True,
            timeout=30,
        )
        return proc.stdout.strip()

    def commit(self, message: str, env: dict[str, str] | None = None) -> str:
        self.git("commit", "-q", "--allow-empty", "-m", message, env=env)
        return self.git("rev-parse", "HEAD")

    def hook(
        self, *lines: str, env: dict[str, str] | None = None
    ) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            ["sh", str(HOOK), "origin", "git@example.invalid:owner/repo.git"],
            input="".join(f"{line}\n" for line in lines),
            cwd=self.root,
            env={**self.env, **(env or {})},
            capture_output=True,
            text=True,
            check=False,
            timeout=30,
        )


@pytest.fixture
def repo(tmp_path: Path) -> Repo:
    return Repo(tmp_path)


def new_branch(sha: str, branch: str = "step/01-x") -> str:
    return f"refs/heads/{branch} {sha} refs/heads/{branch} {ZERO}"


def test_owner_commit_to_a_step_branch_is_allowed(repo: Repo) -> None:
    sha = repo.commit("feat: owner commit")
    assert repo.hook(new_branch(sha)).returncode == 0
    assert repo.hook(new_branch(sha, "security/redteam-v0.1")).returncode == 0


def test_fast_forward_is_allowed(repo: Repo) -> None:
    old = repo.commit("feat: one")
    new = repo.commit("feat: two")
    assert repo.hook(f"refs/heads/step/x {new} refs/heads/step/x {old}").returncode == 0


@pytest.mark.parametrize(
    "message",
    [
        "feat: x\n\nCo-Authored-By: Claude <noreply@anthropic.com>",
        "feat: x\n\nCo-authored-by: A Person <a@example.invalid>",
        "feat: x\n\nClaude-Session: https://claude.ai/code/session",
        "feat: x\n\nGenerated with [Claude Code](https://claude.com/claude-code)",
    ],
)
def test_attribution_lines_are_refused(repo: Repo, message: str) -> None:
    sha = repo.commit(message)
    proc = repo.hook(new_branch(sha))
    assert proc.returncode == 1
    assert "attribution" in proc.stderr


@pytest.mark.parametrize("who", ["AUTHOR", "COMMITTER"])
def test_another_author_or_committer_is_refused(repo: Repo, who: str) -> None:
    sha = repo.commit(
        "feat: x",
        env={f"GIT_{who}_NAME": "Claude", f"GIT_{who}_EMAIL": "noreply@anthropic.com"},
    )
    assert repo.hook(new_branch(sha)).returncode == 1


@pytest.mark.parametrize(
    "remote_ref",
    [
        "refs/heads/main",
        "refs/heads/feature/x",
        "refs/heads/step",
        "refs/notes/commits",
    ],
)
def test_pushes_outside_step_and_security_branches_are_refused(repo: Repo, remote_ref: str) -> None:
    sha = repo.commit("feat: owner commit")
    proc = repo.hook(f"refs/heads/main {sha} {remote_ref} {ZERO}")
    assert proc.returncode == 1
    assert "refusing to push" in proc.stderr


def test_deletion_is_refused(repo: Repo) -> None:
    sha = repo.commit("feat: owner commit")
    proc = repo.hook(f"(delete) {ZERO} refs/heads/step/x {sha}")
    assert proc.returncode == 1
    assert "delete" in proc.stderr


def test_force_push_is_refused(repo: Repo) -> None:
    base = repo.commit("feat: base")
    remote_tip = repo.commit("feat: on the remote")
    repo.git("reset", "-q", "--hard", base)
    local_tip = repo.commit("feat: rewritten")
    proc = repo.hook(f"refs/heads/step/x {local_tip} refs/heads/step/x {remote_tip}")
    assert proc.returncode == 1
    assert "non-fast-forward" in proc.stderr


def test_unknown_remote_tip_fails_closed(repo: Repo) -> None:
    sha = repo.commit("feat: owner commit")
    proc = repo.hook(f"refs/heads/step/x {sha} refs/heads/step/x {'a' * 40}")
    assert proc.returncode == 1


def test_tags_need_the_release_flag(repo: Repo) -> None:
    sha = repo.commit("feat: owner commit")
    line = f"refs/tags/v0.1.0 {sha} refs/tags/v0.1.0 {ZERO}"
    assert repo.hook(line).returncode == 1
    assert repo.hook(line, env={"AIPM_RELEASE_TAG": "1"}).returncode == 0
    other = f"refs/tags/nightly {sha} refs/tags/nightly {ZERO}"
    assert repo.hook(other, env={"AIPM_RELEASE_TAG": "1"}).returncode == 1


def test_unknown_local_commit_fails_closed(repo: Repo) -> None:
    repo.commit("feat: owner commit")
    assert repo.hook(new_branch("d" * 40)).returncode == 1


def test_missing_identity_is_refused(repo: Repo) -> None:
    sha = repo.commit("feat: owner commit")
    assert repo.hook(new_branch(sha), env={"GIT_CONFIG_COUNT": "0"}).returncode == 1


def test_one_bad_ref_refuses_the_whole_push(repo: Repo) -> None:
    sha = repo.commit("feat: owner commit")
    proc = repo.hook(new_branch(sha), f"refs/heads/main {sha} refs/heads/main {ZERO}")
    assert proc.returncode == 1
