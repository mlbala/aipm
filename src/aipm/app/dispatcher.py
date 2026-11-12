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

Before each attempt the config home is emptied of everything but the session transcripts (and
re-seeded with the settings aipm gives the tool, ADR-0026), so nothing the agent would run or
obey without asking survives from one attempt to the next.

Without a sandbox the caller has already printed the warning (SECURITY.md §9.1), and the
post-change checks still decide what the agent's changes are worth.
"""

import os
import shutil
from collections.abc import Collection, Sequence
from dataclasses import dataclass
from pathlib import Path

from aipm.adapters.base import (
    AgentResult,
    ConfigHomeSpec,
    DispatchLimits,
    RenderedTaskPrompt,
    ToolAdapter,
)
from aipm.config.schema import Config, SandboxMode, ToolConfig
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


def native_allowed(cfg: Config) -> bool:
    """Whether `dispatch.sandbox` lets an agent use its tool's own sandbox when `srt` is not
    used (`auto` or `tool-native`; SECURITY.md §9.1 calls it the fallback)."""
    return cfg.dispatch.sandbox in (SandboxMode.AUTO, SandboxMode.TOOL_NATIVE)


def tool_limits(
    tool: ToolConfig | None,
    *,
    timeout_s: float,
    task_usd: float,
    allowed_commands: tuple[tuple[str, ...], ...],
    native_sandbox: bool,
) -> DispatchLimits:
    """One attempt's limits from `dispatch.tools.<tool>` (its defaults when it is not set)."""
    settings = tool if tool is not None else ToolConfig()
    return DispatchLimits(
        timeout_s=timeout_s,
        task_usd=task_usd,
        allowed_commands=allowed_commands,
        pass_env=tuple(settings.pass_env),
        allow_auto_mode=settings.allow_auto_mode,
        bare=settings.bare,
        native_sandbox=native_sandbox,
    )


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


def config_home_hashes(
    config_home: Path, protected: Sequence[str] = CONFIG_HOME_PROTECTED
) -> dict[str, str | None]:
    """The hashes of what the tool would read as settings from the agent's config home
    (ADR-0023, ADR-0026): compared before and after each attempt, a change is a severe
    violation."""
    return {rel: git.hash_path(config_home / rel) for rel in protected}


CONFIG_HOME_KEEP: frozenset[str] = frozenset({"projects"})
"""What survives from one attempt to the next in the agent's config home: the session
transcripts `--resume` reads (red-team v0.3)."""


def reset_config_home(config_home: Path, keep: Collection[str] = CONFIG_HOME_KEEP) -> None:
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
        if entry.name in keep and entry.is_dir(follow_symlinks=False):
            continue
        if entry.is_dir(follow_symlinks=False):
            shutil.rmtree(entry.path)
        else:
            Path(entry.path).unlink()


def seed_config_home(config_home: Path, seed: Sequence[tuple[str, str]]) -> None:
    """Write the files aipm gives the tool in its config home (`ConfigHomeSpec.seed`), after
    `reset_config_home`: each is created new, mode 0600, never through a link."""
    for rel, text in seed:
        parts = Path(rel).parts
        if not parts or Path(rel).is_absolute() or ".." in parts:
            raise PolicyViolation(f"the config home file {rel!r} is not a plain relative path")
        parent = config_home
        for part in parts[:-1]:
            parent = parent / part
            if parent.is_symlink():
                raise PolicyViolation(f"{parent} is a link; refusing to write through it")
            parent.mkdir(mode=0o700, exist_ok=True)
        write_new(config_home / rel, text)


def prepare_config_home(config_home: Path, spec: ConfigHomeSpec) -> dict[str, str | None]:
    """Empty the config home but for `spec.keep`, write `spec.seed`, and return the hashes of
    `spec.protected` that the attempt must leave unchanged."""
    reset_config_home(config_home, spec.keep)
    seed_config_home(config_home, spec.seed)
    return config_home_hashes(config_home, spec.protected)


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
            config_home_protected=adapter.config_home.protected,
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
