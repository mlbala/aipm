"""Sandboxing with `srt`, from the table in SECURITY.md §9.1 (C-13, ADR-0013, ADR-0020).

`profile_for` builds the rules for one process, `wrap` writes them to a 0600 settings file in the
per-attempt temp dir and returns the argv that runs under `srt`, and `resolve_sandbox` decides
whether a sandbox can be used. `security.require_sandbox` makes a missing one exit 8; otherwise
every use prints a warning.

What `srt` 0.0.81 does, and what aipm does about it (ADR-0020):

- It does not exec an argv: it shell-quotes its arguments and runs the result through a shell.
  So `wrap` refuses (exit 6) any element whose quoting would depend on more than single quotes.
- Its own exit 1 cannot be told from a command's, so `resolve_sandbox` runs a probe first.
- On macOS a settings path is a glob pattern unless it is written as `{"path", "literal"}`, so
  every path aipm writes is literal.
- Its domain allowlist has no entry for every domain, so the `open` profile cannot run under it
  (exit 8); `strictAllowlist` is set, so the list is enforced, never a hint.
- A command that dies of SIGTERM or SIGINT makes it exit 0, so a gate whose report says how the
  tests went is judged on that report too (`aipm.gates.command_gate`).

`run_safe(sandbox=...)` calls `wrap`, so no caller can forget it.
"""

import json
import os
import secrets
import shutil
from collections.abc import Sequence
from dataclasses import dataclass, field
from enum import StrEnum
from pathlib import Path

from aipm.domain.errors import MissingCapability, PolicyViolation
from aipm.domain.models import NetworkProfile
from aipm.security.network import NetworkPolicy

_SHELL_ACTIVE = frozenset("'\"`$\\!")
_GLOB_CHARS = frozenset("*?[]{}")
PROBE_TIMEOUT_S = 30.0
INSTALL_HINT = (
    "Install it with `npm install -g @anthropic-ai/sandbox-runtime` "
    "(macOS also needs ripgrep; Linux needs bubblewrap, socat and ripgrep)."
)

CREDENTIAL_PATHS: tuple[str, ...] = (
    ".ssh", ".aws", ".config/gcloud", ".kube", ".docker", ".netrc", ".git-credentials", ".gnupg",
    ".config/gh", "Library/Keychains", ".local/share/keyrings",
    "Library/Application Support/Google/Chrome", "Library/Application Support/Firefox",
    "Library/Application Support/BraveSoftware", "Library/Safari",
    ".config/google-chrome", ".config/chromium", ".mozilla",
)  # fmt: skip
"""SECURITY.md §3 developer credentials, relative to the home directory."""

AGENT_HOMES: tuple[str, ...] = (".claude", ".codex", ".gemini", ".copilot")
"""The coding agents' global config homes, relative to home. In manual mode they are the agent's
config home, which gates may not read (SECURITY.md §9.1): some hold login tokens."""

AGENT_GLOBAL_CONFIG: tuple[str, ...] = (
    ".claude/settings.json", ".claude/settings.local.json", ".claude/CLAUDE.md",
    ".claude/hooks", ".claude/agents", ".claude/skills", ".claude/commands", ".claude/plugins",
    ".codex/config.toml", ".codex/AGENTS.md", ".codex/skills",
    ".gemini/settings.json", ".gemini/GEMINI.md", ".copilot/config.json",
)  # fmt: skip
"""Agents' global settings, hooks, plugins and skills, relative to home (SECURITY.md §9.1)."""

PACKAGE_CACHES: tuple[str, ...] = (
    ".cache/uv", ".cache/pip", "Library/Caches/uv", "Library/Caches/pip",
    ".npm", ".cache/pnpm", ".local/share/pnpm", "Library/pnpm", "Library/Caches/pnpm",
)  # fmt: skip
"""Where package managers keep their caches, relative to home; only `prepare` may write there."""

_PROTECTED_LITERALS: tuple[str, ...] = (
    ".pm", ".git", ".github", ".gitlab-ci.yml", "AGENTS.md", "CLAUDE.md", "GEMINI.md", ".claude",
    ".gemini", ".codex", ".agents", ".mcp.json", ".gitattributes", ".gitmodules", ".aipmignore",
)  # fmt: skip
"""SECURITY.md §9.2 as literal paths. `**/.env*` is added as a pattern, which only macOS applies;
the protected-path check after the gates catches a change to one anywhere."""

ENV_PATTERN = "**/.env*"


class ProcessKind(StrEnum):
    """The rows of the table in SECURITY.md §9.1."""

    AGENT = "agent"
    GATE = "gate"
    PREPARE = "prepare"
    SCANNER = "scanner"


@dataclass(frozen=True, slots=True)
class ProfilePaths:
    """The directories one profile is built from. `temp_dir` is per attempt, mode 0700."""

    workspace: Path
    temp_dir: Path
    home: Path
    config_home: Path | None = None
    main_pm: Path | None = None
    other_worktrees: tuple[Path, ...] = ()
    output_dir: Path | None = None


@dataclass(frozen=True, slots=True)
class SandboxProfile:
    """Filesystem and network rules for one process, and where to write its settings.

    `deny_write_patterns` are glob patterns (macOS only); every other path is literal.
    """

    kind: ProcessKind
    network: NetworkPolicy
    runtime: str
    settings_dir: Path
    allow_write: tuple[Path, ...] = ()
    deny_read: tuple[Path, ...] = ()
    deny_write: tuple[Path, ...] = field(default_factory=tuple[Path, ...])
    deny_write_patterns: tuple[str, ...] = ()


def profile_for(
    kind: ProcessKind, network: NetworkPolicy, paths: ProfilePaths, *, runtime: str
) -> SandboxProfile:
    """The profile for one process, from the table in SECURITY.md §9.1."""
    home = paths.home
    deny_read = [home / rel for rel in CREDENTIAL_PATHS]
    if kind is ProcessKind.AGENT:
        allow = [paths.workspace, paths.temp_dir]
        allow += [] if paths.config_home is None else [paths.config_home]
        deny_read += [] if paths.main_pm is None else [paths.main_pm]
        deny_read += list(paths.other_worktrees)
    elif kind is ProcessKind.GATE:
        allow = [paths.workspace, paths.temp_dir]
        if paths.config_home is not None:
            deny_read.append(paths.config_home)
        else:
            deny_read += [home / rel for rel in AGENT_HOMES]
    elif kind is ProcessKind.PREPARE:
        allow = [paths.workspace, paths.temp_dir, *(home / rel for rel in PACKAGE_CACHES)]
    else:
        allow = [paths.output_dir if paths.output_dir is not None else paths.temp_dir]
    deny_write = [paths.workspace / rel for rel in _PROTECTED_LITERALS]
    deny_write += [home / rel for rel in AGENT_GLOBAL_CONFIG]
    workspace = str(paths.workspace)
    patterns = () if _GLOB_CHARS & set(workspace) else (f"{workspace}/{ENV_PATTERN}",)
    return SandboxProfile(
        kind=kind,
        network=network,
        runtime=runtime,
        settings_dir=paths.temp_dir,
        allow_write=tuple(allow),
        deny_read=tuple(deny_read),
        deny_write=tuple(deny_write),
        deny_write_patterns=patterns,
    )


def _literal(paths: Sequence[Path]) -> list[dict[str, object]]:
    return [{"path": str(p), "literal": True} for p in paths]


def settings_document(profile: SandboxProfile) -> dict[str, object]:
    """The `srt` settings: writes and network are allow-only, so what is not named is denied.

    `open` raises `MissingCapability` (exit 8): `srt` has no allowlist entry for every domain,
    and running the process without the sandbox instead would be a silent downgrade.
    """
    if profile.network.profile is NetworkProfile.OPEN:
        raise MissingCapability(
            f"the {profile.kind.value} network profile is open, which srt cannot express",
            hint="Choose another profile in security.network, or set dispatch.sandbox: none in "
            "your user config to run without a sandbox (and with a warning).",
        )
    return {
        "network": {
            "allowedDomains": list(profile.network.domains),
            "deniedDomains": [],
            "strictAllowlist": True,
        },
        "filesystem": {
            "denyRead": _literal(profile.deny_read),
            "allowWrite": _literal(profile.allow_write),
            "denyWrite": [*_literal(profile.deny_write), *profile.deny_write_patterns],
        },
    }


def check_shell_safe(argv: Sequence[str]) -> None:
    """Refuse (exit 6) an element that `srt`'s shell could read as more than one literal word.

    Without these characters, shell-quote takes its plain single-quote or backslash path. A word
    that is empty would vanish, and a leading `~` would expand (ADR-0020).
    """
    for arg in argv:
        if not arg:
            raise PolicyViolation("an empty argv element cannot run inside the sandbox")
        if arg.startswith("~"):
            raise PolicyViolation(f"argv element {arg!r} starts with ~, which a shell expands")
        if any(ch in _SHELL_ACTIVE or not ch.isprintable() for ch in arg):
            raise PolicyViolation(
                f"argv element {arg!r} holds a character that is not safe inside the sandbox's "
                "shell",
                hint="Remove quotes, $, backslashes, backticks and ! from the gate command or "
                "the file name.",
            )


def wrap(argv: Sequence[str], profile: SandboxProfile) -> tuple[str, ...]:
    """The argv that runs `argv` under `srt`, with the settings written 0600.

    A runtime that is gone raises `MissingCapability` (exit 8): nothing runs unsandboxed because
    a profile could not be applied.
    """
    if not os.access(profile.runtime, os.X_OK):
        raise MissingCapability(
            f"the sandbox runtime {profile.runtime} cannot be run", hint=INSTALL_HINT
        )
    check_shell_safe(argv)
    document = settings_document(profile)
    name = f"srt-{profile.kind.value}-{secrets.token_hex(6)}.json"
    target = profile.settings_dir / name
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW
    data = json.dumps(document, indent=2).encode("utf-8")
    fd = os.open(target, flags, 0o600)
    with os.fdopen(fd, "wb") as handle:
        handle.write(data)
    return (profile.runtime, "--settings", str(target), "--", *argv)


@dataclass(frozen=True, slots=True)
class SandboxStatus:
    """Whether processes can run under a sandbox, and the warning to print on every use if not."""

    runtime: str | None
    warning: str | None = None


def _probe(runtime: str, temp_dir: Path) -> str | None:
    """Run a harmless program under a no-network profile; returns why it failed, if it did."""
    from aipm.execution.process import build_env, run_safe  # noqa: PLC0415 - process imports us

    target = shutil.which("true") or "/usr/bin/true"
    paths = ProfilePaths(workspace=temp_dir, temp_dir=temp_dir, home=Path.home())
    network = NetworkPolicy(NetworkProfile.NONE)
    profile = profile_for(ProcessKind.GATE, network, paths, runtime=runtime)
    result = run_safe(
        [target],
        cwd=temp_dir,
        env=build_env(),
        timeout_s=PROBE_TIMEOUT_S,
        max_output_bytes=8192,
        sandbox=profile,
    )
    if result.returncode == 0 and not result.timed_out:
        return None
    detail = result.stderr.decode("utf-8", errors="replace").strip().splitlines()
    return detail[0][:200] if detail else f"exit {result.returncode}"


def _runtime(repo: Path) -> str | None:
    from aipm.execution.process import is_inside  # noqa: PLC0415 - process imports us

    found = shutil.which("srt")
    if found is None:
        return None
    if is_inside(found, repo):
        raise PolicyViolation(
            f"the srt found on PATH ({found}) is inside the repository",
            hint="Remove relative or repository entries from PATH.",
        )
    return found


def resolve_sandbox(
    *, mode: str, require: bool, repo: Path, temp_dir: Path, what: str = "gates"
) -> SandboxStatus:
    """Decide how `what` run: under `srt`, or without a sandbox and with a warning.

    `dispatch.sandbox: none` turns the sandbox off, unless `security.require_sandbox` is set. A
    required sandbox that is missing or fails the probe exits 8, and so does `dispatch.sandbox:
    srt`. `tool-native` means nothing for gates, so it acts like `auto` here.
    """
    if mode == "none" and not require:
        return SandboxStatus(None, f"dispatch.sandbox is none: {what} run without a sandbox")
    runtime = None if mode == "none" else _runtime(repo)
    reason = "dispatch.sandbox is none" if mode == "none" else "srt is not installed"
    if runtime is not None:
        failure = _probe(runtime, temp_dir)
        if failure is None:
            return SandboxStatus(runtime)
        reason = f"srt could not start a sandbox ({failure})"
    if require or mode == "srt":
        raise MissingCapability(
            f"a sandbox is required, and {reason}",
            hint=INSTALL_HINT,
        )
    return SandboxStatus(None, f"{reason}: {what} run without a sandbox. {INSTALL_HINT}")
