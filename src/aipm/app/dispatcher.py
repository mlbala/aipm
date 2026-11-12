"""Dispatch one task attempt to a coding agent (C-18, ARCHITECTURE §12.4 step 2, SECURITY §9).

The adapter builds the invocation from fixed fragments; here the forbidden-flag check runs again
on the final argv, the context file is written (never through a link, never over a file), and
the agent runs through `run_safe_async`: in its worktree, with the built environment, the
attempt's timeout, a 2 MB output cap and, when `srt` is available, the agent sandbox profile:

- writes: the worktree, the agent's temp dir and its config home (not the settings there);
- reads denied: credential directories, the agents' own homes, every top-level entry of the
  main checkout except `.git`, every other task's worktree and config home, and the rebase
  directory (ADR-0024);
- network: the agent's profile (`api-only`: the tool's API domains only).

Before each attempt the config home is emptied of everything but the session transcripts, so
nothing Claude Code would run or obey without asking survives from one attempt to the next.

Without a sandbox the caller has already printed the warning (SECURITY.md §9.1), and the
post-change checks still decide what the agent's changes are worth.
"""

import os
import shutil
from dataclasses import dataclass
from pathlib import Path

from aipm.adapters.base import AgentResult, DispatchLimits, RenderedTaskPrompt, ToolAdapter
from aipm.domain.errors import PolicyViolation
from aipm.domain.models import NetworkProfile, Workspace
from aipm.execution import git
from aipm.execution.process import ProcessResult, run_safe_async
from aipm.execution.sandbox import (
    CONFIG_HOME_PROTECTED,
    ProcessKind,
    ProfilePaths,
    Runtime,
    main_repo_entries,
    path_dirs,
    profile_for,
)
from aipm.security.command_policy import check_forbidden_flags
from aipm.security.network import NetworkPolicy, allowed_domains

MAX_AGENT_OUTPUT = 2_000_000


@dataclass(frozen=True, slots=True)
class Dispatch:
    """One agent run: the parsed result and the raw process outcome."""

    result: AgentResult
    process: ProcessResult
    argv: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class Isolation:
    """What the agent's sandbox keeps it from: everything but its own worktree.

    `other_worktrees` names every other task's worktree and config home, whether it exists yet
    or not, and the directory rebases run in; `main_repo` is the main checkout, of which the
    agent may read only `.git` (ADR-0024).
    """

    runtime: Runtime | None
    home: Path
    main_pm: Path
    other_worktrees: tuple[Path, ...]
    network: NetworkProfile
    main_repo: Path | None = None


def agent_network(profile: NetworkProfile, api_domains: tuple[str, ...]) -> NetworkPolicy:
    """The agent's network policy: `api-only` names the tool's API domains (SECURITY.md §9.1)."""
    if profile is NetworkProfile.API_ONLY:
        return NetworkPolicy(profile, allowed_domains(profile, api_domains=api_domains))
    return NetworkPolicy(profile)


def write_new(path: Path, text: str) -> None:
    """Create `path` with `text`, mode 0600; refuse to follow a link or reuse a file."""
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW
    try:
        fd = os.open(path, flags, 0o600)
    except FileExistsError:
        raise PolicyViolation(f"{path} already exists; refusing to reuse it") from None
    with os.fdopen(fd, "w", encoding="utf-8") as handle:
        handle.write(text)


def config_home_hashes(config_home: Path) -> dict[str, str | None]:
    """The hashes of what Claude Code would read as settings from the agent's config home
    (ADR-0023): compared before and after each attempt, a change is a severe violation."""
    return {rel: git.hash_path(config_home / rel) for rel in CONFIG_HOME_PROTECTED}


CONFIG_HOME_KEEP: frozenset[str] = frozenset({"projects"})
"""What survives from one attempt to the next in the agent's config home: the session
transcripts `--resume` reads (red-team v0.3)."""


def reset_config_home(config_home: Path) -> None:
    """Remove everything but `CONFIG_HOME_KEEP` from the agent's config home, never following a
    link (red-team v0.3).

    Claude Code runs `shell-snapshots/` and `session-env/` before every Bash command, its
    background service starts what `daemon.json` and `daemon/` list, and `.claude.json` holds
    per-project tool grants and trust. Gate code the agent ran can write any of them, so none
    may reach the next attempt; Claude Code makes what it needs again.
    """
    try:
        entries = list(os.scandir(config_home))
    except FileNotFoundError:
        return
    for entry in entries:
        if entry.name in CONFIG_HOME_KEEP and entry.is_dir(follow_symlinks=False):
            continue
        if entry.is_dir(follow_symlinks=False):
            shutil.rmtree(entry.path)
        else:
            Path(entry.path).unlink()


async def dispatch(
    adapter: ToolAdapter,
    prompt: RenderedTaskPrompt,
    limits: DispatchLimits,
    ws: Workspace,
    isolation: Isolation,
) -> Dispatch:
    """Run the agent for one attempt; `PolicyViolation` (exit 6) for a forbidden flag."""
    invocation = adapter.build_invocation(prompt, limits, ws)
    check_forbidden_flags(adapter.name, invocation.argv, allow_auto_mode=limits.allow_auto_mode)
    for path, text in invocation.files:
        write_new(path, text)
    profile = None
    if isolation.runtime is not None:
        programs = tuple(Path(p) for p in invocation.programs)
        keep = (ws.root, ws.temp_dir, ws.context_dir, ws.config_home, *programs, *path_dirs())
        main = (
            () if isolation.main_repo is None else main_repo_entries(isolation.main_repo, keep=keep)
        )
        paths = ProfilePaths(
            workspace=ws.root,
            temp_dir=ws.temp_dir,
            home=isolation.home,
            config_home=ws.config_home,
            main_pm=isolation.main_pm,
            other_worktrees=isolation.other_worktrees,
            extra_deny_read=main,
            keep_readable=programs,
        )
        network = agent_network(isolation.network, invocation.api_domains)
        profile = profile_for(ProcessKind.AGENT, network, paths, runtime=isolation.runtime)
    out = await run_safe_async(
        invocation.argv,
        cwd=ws.root,
        env=invocation.env,
        timeout_s=limits.timeout_s,
        stdin=invocation.stdin,
        max_output_bytes=MAX_AGENT_OUTPUT,
        sandbox=profile,
    )
    return Dispatch(adapter.parse_result(out), out, invocation.argv)
