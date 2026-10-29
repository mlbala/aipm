"""Hardened git calls (SECURITY.md §11): hooks off, no fsmonitor, no external diff, no pager.

Every call goes through `run_safe` with an argv list, a constructed environment, a timeout and
an output cap. The `-c` options come first, so a repository's own `.git/config` cannot name a
hook directory or an fsmonitor program for git to run. v0.1 needs only `head_sha`; the rest of
the wrapper arrives with build prompt 06.
"""

import re
import shutil
from pathlib import Path

from aipm.domain.errors import MissingCapability, PolicyViolation, UsageError
from aipm.domain.models import ChangeSet
from aipm.execution.process import build_env, is_inside, run_safe

GIT_TIMEOUT_S = 30.0
HARDENING: tuple[str, ...] = (
    "-c", "core.hooksPath=/dev/null",
    "-c", "core.fsmonitor=false",
    "-c", "diff.external=",
    "-c", "core.pager=cat",
    "--no-pager",
)  # fmt: skip
"""Options that go before every git subcommand."""
GIT_ENV: dict[str, str] = {
    "GIT_TERMINAL_PROMPT": "0",
    "GIT_OPTIONAL_LOCKS": "0",
    "GIT_CONFIG_NOSYSTEM": "1",
}
_SHA = re.compile(r"[0-9a-f]{40}(?:[0-9a-f]{24})?")


def git_argv(repo: Path, *args: str) -> list[str]:
    """`git` (resolved on PATH), the hardening options, then `args`.

    Exit 8 without git; exit 6 if the `git` found on PATH lies inside the repository.
    """
    git = shutil.which("git")
    if git is None:
        raise MissingCapability("git is not installed or not on PATH")
    if is_inside(git, repo):
        raise PolicyViolation(
            f"the git found on PATH ({git}) is inside the repository",
            hint="Remove relative or repository entries from PATH.",
        )
    return [git, *HARDENING, *args]


def head_sha(repo: Path) -> str:
    """The commit `HEAD` points at, as 40 (or 64) hex characters.

    Raises `UsageError` (exit 2) when there is no commit yet, or git cannot read the repository.
    """
    result = run_safe(
        git_argv(repo, "rev-parse", "--verify", "--quiet", "HEAD^{commit}"),
        cwd=repo,
        env=build_env(extra=GIT_ENV),
        timeout_s=GIT_TIMEOUT_S,
        max_output_bytes=4096,
    )
    sha = result.stdout.decode("ascii", errors="replace").strip()
    if result.returncode != 0 or not _SHA.fullmatch(sha):
        raise UsageError(
            "cannot resolve HEAD: the repository has no commit yet, or git cannot read it",
            hint="Commit your work first; aipm records HEAD as the task's base commit.",
        )
    return sha


def change_set(repo: Path, base_sha: str) -> ChangeSet:
    """Collect the facts that post-change checks inspect."""
    raise NotImplementedError("v0.2: build prompt 06")
