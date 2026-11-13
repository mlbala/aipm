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
    ".config/gh", ".npmrc", ".pypirc", ".cargo/credentials", ".cargo/credentials.toml",
    ".azure", ".config/op", "Library/Keychains", ".local/share/keyrings",
    "Library/Application Support/Google/Chrome", "Library/Application Support/Firefox",
    "Library/Application Support/BraveSoftware", "Library/Safari",
    ".config/google-chrome", ".config/chromium", ".mozilla",
    # Red-team v0.3 (ADR-0024): the agents' login tokens, where Claude Code keeps an API key
    # typed at /login (`~/.claude.json`), other well-known token files, and shell and REPL
    # histories, where tokens typed on a command line end up.
    ".claude.json", ".claude/.credentials.json", ".codex/auth.json",
    ".gemini/oauth_creds.json", ".gemini/google_accounts.json",
    ".vault-token", ".pgpass", ".my.cnf", ".terraform.d/credentials.tfrc.json", ".config/hub",
    ".m2/settings.xml", ".gradle/gradle.properties", ".fly", ".config/doctl",
    ".bash_history", ".zsh_history", ".zsh_sessions", ".local/share/fish/fish_history",
    ".python_history", ".node_repl_history", ".psql_history", ".mysql_history",
    ".sqlite_history",
    # Step 08 review: a dotenv file in the home directory, which tools that search upward for
    # `.env` (Gemini CLI) would load.
    ".env",
)  # fmt: skip
"""SECURITY.md §3 developer credentials, relative to the home directory."""

AGENT_HOMES: tuple[str, ...] = (".claude", ".codex", ".gemini", ".copilot")
"""The coding agents' global config homes, relative to home. In manual mode they are the agent's
config home, which gates may not read (SECURITY.md §9.1): some hold login tokens. A dispatched
agent with a config home of its own may not read them either (ADR-0024), unless its own program
lies inside one (a Claude Code installed under `~/.claude/local`)."""

MAX_MAIN_ENTRIES = 4096
"""The most top-level entries of the main repository a profile denies one by one (ADR-0024)."""

AGENT_GLOBAL_CONFIG: tuple[str, ...] = (
    ".claude/settings.json", ".claude/settings.local.json", ".claude/CLAUDE.md",
    ".claude/hooks", ".claude/agents", ".claude/skills", ".claude/commands", ".claude/plugins",
    ".claude/daemon.json", ".claude/daemon", ".claude/jobs", ".claude/shell-snapshots",
    ".claude/session-env",
    ".codex/config.toml", ".codex/AGENTS.md", ".codex/skills",
    ".gemini/settings.json", ".gemini/GEMINI.md", ".copilot/config.json",
)  # fmt: skip
"""Agents' global settings, hooks, plugins and skills, relative to home (SECURITY.md §9.1)."""

CONFIG_HOME_PROTECTED: tuple[str, ...] = (
    "settings.json", "settings.local.json", "CLAUDE.md", "hooks", "agents", "skills",
    "commands", "plugins",
)  # fmt: skip
"""In Claude Code's isolated config home (`CLAUDE_CONFIG_DIR`): what it would read as user
settings on the next `--resume`. The agent may write its sessions there, never these
(ADR-0023). Other tools name theirs in their adapter's `ConfigHomeSpec` (ADR-0026)."""

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
    extra_deny_read: tuple[Path, ...] = ()
    """More paths no process of this profile may read (build gates: the agent's config home)."""
    keep_readable: tuple[Path, ...] = ()
    """Paths the process must read (its own program): an agent home that holds one is not
    denied."""
    config_home_protected: tuple[str, ...] = CONFIG_HOME_PROTECTED
    """What in `config_home` the agent may not write: its tool's settings, hooks and skills
    (`ConfigHomeSpec.protected`)."""


@dataclass(frozen=True, slots=True)
class SandboxProfile:
    """Filesystem and network rules for one process, and where to write its settings.

    `deny_write_patterns` are glob patterns (macOS only); every other path is literal.
    `launcher` is how `srt` is started: its interpreter, resolved outside the repository, then
    `srt` itself (`runtime`); just `srt` when it needs no interpreter from PATH.
    """

    kind: ProcessKind
    network: NetworkPolicy
    runtime: str
    settings_dir: Path
    launcher: tuple[str, ...] = ()
    allow_write: tuple[Path, ...] = ()
    deny_read: tuple[Path, ...] = ()
    deny_write: tuple[Path, ...] = field(default_factory=tuple[Path, ...])
    deny_write_patterns: tuple[str, ...] = ()


type Runtime = str | tuple[str, ...]
"""`srt`'s path, or its launcher (interpreter, then `srt`) from `resolve_sandbox`."""


def profile_for(
    kind: ProcessKind, network: NetworkPolicy, paths: ProfilePaths, *, runtime: Runtime
) -> SandboxProfile:
    """The profile for one process, from the table in SECURITY.md §9.1."""
    launcher = (runtime,) if isinstance(runtime, str) else tuple(runtime)
    home = paths.home
    deny_read = [home / rel for rel in CREDENTIAL_PATHS]
    deny_read += list(paths.extra_deny_read)
    agent_config: list[Path] = []
    if kind is ProcessKind.AGENT:
        allow = [paths.workspace, paths.temp_dir]
        if paths.config_home is not None:
            allow.append(paths.config_home)
            agent_config = [paths.config_home / rel for rel in paths.config_home_protected]
            # With a config home of its own, the agent never needs the user's (ADR-0024).
            deny_read += [
                home / rel
                for rel in AGENT_HOMES
                if not any(holds(home / rel, keep) for keep in paths.keep_readable)
            ]
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
    deny_write += agent_config
    workspace = str(paths.workspace)
    patterns = () if _GLOB_CHARS & set(workspace) else (f"{workspace}/{ENV_PATTERN}",)
    return SandboxProfile(
        kind=kind,
        network=network,
        runtime=launcher[-1],
        launcher=launcher,
        settings_dir=paths.temp_dir,
        allow_write=tuple(allow),
        deny_read=tuple(deny_read),
        deny_write=tuple(deny_write),
        deny_write_patterns=patterns,
    )


def holds(parent: Path, path: Path) -> bool:
    """Whether `path` is `parent` or lies under it, links resolved on both."""
    outer = os.path.realpath(parent)
    inner = os.path.realpath(path)
    return inner == outer or inner.startswith(outer.rstrip(os.sep) + os.sep)


def main_repo_entries(repo: Path, *, keep: Sequence[Path]) -> tuple[Path, ...]:
    """What a process whose workspace is a task worktree may not read of the main repository
    (ADR-0024): every top-level entry but `.git`, whose objects and config git in the worktree
    reads, and the target of every top-level link. The worktree lives outside the repository,
    so nothing in it needs the main checkout, which holds the user's ignored `.env` and keys.

    An entry that holds a path in `keep` (the process's workspace, temp dir, config home and
    programs, and the `PATH` directories) is left out, so a repository that is the home
    directory still runs. More than `MAX_MAIN_ENTRIES` entries exits 6.
    """
    root = Path(os.path.realpath(repo))
    try:
        names = sorted(entry.name for entry in root.iterdir())
    except OSError as exc:
        raise PolicyViolation(f"aipm cannot list the repository {root}: {exc.strerror}") from None
    if len(names) > MAX_MAIN_ENTRIES:
        raise PolicyViolation(
            f"the repository has more than {MAX_MAIN_ENTRIES} top-level entries, more than a "
            "sandbox profile hides one by one",
            hint="Move files into directories, or run tasks yourself with `aipm prompt`.",
        )
    denied: list[Path] = []
    for name in names:
        if name == ".git":
            continue
        entry = root / name
        targets = [entry, Path(os.path.realpath(entry))] if entry.is_symlink() else [entry]
        denied += [t for t in targets if not any(holds(t, k) for k in keep)]
    return tuple(denied)


def path_dirs() -> tuple[Path, ...]:
    """The absolute directories on `PATH`, which the programs a process runs come from."""
    found = (os.environ.get("PATH") or "").split(os.pathsep)
    return tuple(Path(p) for p in found if p and Path(p).is_absolute())


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
    launcher = profile.launcher or (profile.runtime,)
    if not os.access(launcher[0], os.X_OK) or not os.access(profile.runtime, os.R_OK):
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
    return (*launcher, "--settings", str(target), "--", *argv)


@dataclass(frozen=True, slots=True)
class SandboxStatus:
    """Whether processes can run under a sandbox, and the warning to print on every use if not.

    `launcher` is what to pass on as the runtime: `srt`, or its interpreter and `srt`.
    """

    runtime: str | None
    warning: str | None = None
    launcher: tuple[str, ...] | None = None


def which_outside(name: str, repo: Path, *, also: Sequence[Path] = ()) -> str | None:
    """`name` on PATH, skipping relative entries and every entry inside the repository (or
    inside `also`: aipm's task worktrees, which agents write)."""
    from aipm.execution.process import is_inside  # noqa: PLC0415 - process imports us

    roots = (repo, *also)
    for entry in os.environ.get("PATH", "").split(os.pathsep):
        if not entry or not Path(entry).is_absolute() or any(is_inside(entry, r) for r in roots):
            continue
        candidate = Path(entry) / name
        usable = candidate.is_file() and os.access(candidate, os.X_OK)
        if usable and not any(is_inside(str(candidate), r) for r in roots):
            return str(candidate)
    return None


def launcher_for(
    srt: str,
    repo: Path,
    *,
    name: str = "srt",
    hint: str = INSTALL_HINT,
    also: Sequence[Path] = (),
) -> tuple[str, ...]:
    """How to start a script without trusting PATH for its interpreter (step 06 review).

    `srt` (and an npm-installed `claude`) is a `#!/usr/bin/env node` script: the kernel would
    look `node` up on the PATH aipm passes on, where a repository-local entry (an active
    `.venv/bin`, `node_modules/.bin`) could come first. So the interpreter is resolved here,
    outside the repository, and started explicitly. An absolute interpreter inside the
    repository exits 6; a first line aipm cannot read exits 8. A native binary starts as is.
    """
    from aipm.execution.process import is_inside  # noqa: PLC0415 - process imports us

    try:
        with Path(srt).open("rb") as handle:
            first = handle.read(256).split(b"\n", 1)[0]
    except OSError:
        raise MissingCapability(f"cannot read {srt}", hint=hint) from None
    if not first.startswith(b"#!"):
        return (srt,)
    words = first[2:].decode("utf-8", errors="replace").split()
    if not words:
        raise MissingCapability(f"cannot tell how to start {srt}", hint=hint)
    if Path(words[0]).name == "env":
        if len(words) != 2 or words[1].startswith("-"):
            raise MissingCapability(f"cannot tell how to start {srt}: {first[:80]!r}")
        found = which_outside(words[1], repo, also=also)
        if found is None:
            raise MissingCapability(
                f"{name} needs {words[1]}, which is not on PATH outside the repository",
                hint=hint,
            )
        return (found, srt)
    if any(is_inside(words[0], root) for root in (repo, *also)):
        raise PolicyViolation(f"{name}'s interpreter {words[0]} is inside the repository")
    return (srt,)


def _probe(runtime: Runtime, temp_dir: Path) -> str | None:
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
        launcher = launcher_for(runtime, repo)
        failure = _probe(launcher, temp_dir)
        if failure is None:
            return SandboxStatus(runtime, launcher=launcher)
        reason = f"srt could not start a sandbox ({failure})"
    if require or mode == "srt":
        raise MissingCapability(
            f"a sandbox is required, and {reason}",
            hint=INSTALL_HINT,
        )
    return SandboxStatus(None, f"{reason}: {what} run without a sandbox. {INSTALL_HINT}")
