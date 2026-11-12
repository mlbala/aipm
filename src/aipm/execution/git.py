"""Hardened git calls (SECURITY.md §11): hooks off, no fsmonitor, no external diff, no pager.

Every call goes through `run_safe` with an argv list, a constructed environment, a timeout and
an output cap. The `-c` options come first, so a repository's own `.git/config` cannot name a
hook directory or an fsmonitor program for git to run; diffs also get `--no-ext-diff` and
`--no-textconv`, pathspecs are literal (`GIT_LITERAL_PATHSPECS`), and every path list is `-z`.

Change sets are listed against a fresh index of the base commit, never the user's own (where a
file can be flagged assume-unchanged or skip-worktree), and `GIT_NO_REPLACE_OBJECTS` is set on
every call, so a replace ref cannot swap in a forged base. Git still reads `.git/config`, the
files it includes, `.git/info/attributes` and the user's global config, where clean filters
live. So `change_set` compares their hashes with the attempt snapshot first, without running git
at all: a changed one is a severe violation, and git is not started on it (ADR-0021).

`commit` runs `git commit --no-verify` with signing taken from the user's global config, never
the repository's (`gpg.program`, `gpg.ssh.program`, `gpg.x509.program`, `gpg.format`,
`commit.gpgsign`).

A repository copied with its `.git` directory (a tarball, a copied checkout) brings its own
`.git/config`, and git runs programs named there that the options above do not reach (red-team
v0.2, RT02-1, ADR-0022). So every call also gets, through git's `GIT_CONFIG_*` environment
(the same precedence as `-c`): `hook.<event>.enabled=false` for every hook event, because git
2.5x runs hooks named in config (`hook.<name>.command`) whatever `core.hooksPath` and
`--no-verify` say; `gc.auto=0` and `maintenance.auto=false`; and no lazy fetch from a promisor
remote and no transport at all (`GIT_NO_LAZY_FETCH`, `GIT_ALLOW_PROTOCOL`), since a remote URL
can name a command (`ext::`). Before git compares or stages work-tree files, `check_repo_config`
refuses (exit 6) a repository whose own config names a filter driver, a merge driver, a hook
command, an SSH signing-key command or another work tree.

The build loop (v0.3) adds branches, worktrees and integration: task worktrees on
`aipm/task/<T>`, rebasing a task commit onto the integration branch, and compare-and-swap ref
updates, so a ref that moved under aipm is never overwritten. Signature checks, submodule
recursion, rerere and autostash are off for every call. aipm never pushes or fetches.
"""

import hashlib
import os
import re
import shutil
import stat
import tempfile
from collections.abc import Callable, Generator, Mapping, Sequence
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import Protocol

from aipm.domain.errors import MissingCapability, PolicyViolation, UsageError
from aipm.domain.models import GITLINK_MODE, SYMLINK_MODE, ChangeSet, ChangeStatus, FileChange
from aipm.execution.process import ProcessResult, build_env, is_inside, run_safe
from aipm.security.paths import is_protected, is_within, protected_patterns

GIT_TIMEOUT_S = 30.0
COMMIT_TIMEOUT_S = 120.0
HARDENING: tuple[str, ...] = (
    "-c", "core.hooksPath=/dev/null",
    "-c", "core.fsmonitor=false",
    "-c", "diff.external=",
    "-c", "core.pager=cat",
    "--no-pager",
)  # fmt: skip
"""Options that go before every git subcommand."""
HOOK_EVENTS: tuple[str, ...] = (
    "applypatch-msg", "pre-applypatch", "post-applypatch", "pre-commit", "pre-merge-commit",
    "prepare-commit-msg", "commit-msg", "post-commit", "pre-rebase", "post-checkout",
    "post-merge", "pre-push", "pre-receive", "update", "proc-receive", "post-receive",
    "post-update", "reference-transaction", "push-to-checkout", "pre-auto-gc", "post-rewrite",
    "sendemail-validate", "fsmonitor-watchman", "p4-changelist", "p4-prepare-changelist",
    "p4-post-changelist", "p4-pre-submit", "post-index-change",
)  # fmt: skip
"""Every hook event in githooks(5). Older git ignores `hook.<event>.enabled`, and has no config
hooks for it to stop."""
CONFIG_OVERRIDES: tuple[tuple[str, str], ...] = (
    *((f"hook.{event}.enabled", "false") for event in HOOK_EVENTS),
    ("gc.auto", "0"),
    ("maintenance.auto", "false"),
    # v0.3 checks out, rebases, merges and logs: none of it may verify signatures (which runs
    # `gpg.program`), enter submodules, replay recorded conflict resolutions or stash.
    ("submodule.recurse", "false"),
    ("log.showSignature", "false"),
    ("merge.verifySignatures", "false"),
    ("rerere.enabled", "false"),
    ("rebase.autoStash", "false"),
    ("rebase.updateRefs", "false"),
    ("rebase.autoSquash", "false"),
)
"""Config set for every call through `GIT_CONFIG_COUNT`, which ranks with `-c` (RT02-1)."""


def _config_env(pairs: Sequence[tuple[str, str]]) -> dict[str, str]:
    env = {"GIT_CONFIG_COUNT": str(len(pairs))}
    for index, (key, value) in enumerate(pairs):
        env[f"GIT_CONFIG_KEY_{index}"] = key
        env[f"GIT_CONFIG_VALUE_{index}"] = value
    return env


GIT_ENV: dict[str, str] = {
    "GIT_TERMINAL_PROMPT": "0",
    "GIT_OPTIONAL_LOCKS": "0",
    "GIT_CONFIG_NOSYSTEM": "1",
    "GIT_NO_REPLACE_OBJECTS": "1",
    "GIT_NO_LAZY_FETCH": "1",
    "GIT_ALLOW_PROTOCOL": "none",
    **_config_env(CONFIG_OVERRIDES),
}
"""`GIT_ALLOW_PROTOCOL` names no real transport, so every one is refused, whatever the
repository's `protocol.*.allow` says; aipm never fetches or pushes (SECURITY.md §11)."""
_LITERAL = {"GIT_LITERAL_PATHSPECS": "1"}
_SHA = re.compile(r"[0-9a-f]{40}(?:[0-9a-f]{24})?")
_REV = re.compile(r"[0-9a-f]{7,64}")
_DIFF_FLAGS = ("--no-ext-diff", "--no-textconv", "--no-renames", "--ignore-submodules=none")

MAX_LIST_BYTES = 32 * 1_048_576
MAX_CHANGES = 2_000
MAX_SNAPSHOT_FILES = 20_000
MAX_CONTENT_BYTES = 262_144
MAX_TOTAL_CONTENT = 48 * 1_048_576
MAX_HASH_BYTES = 64 * 1_048_576
MAX_TREE_ENTRIES = 5_000
_CHUNK = 1_048_576
DIR_MODE = "040000"

SIGNING_DEFAULTS: tuple[tuple[str, str], ...] = (
    ("commit.gpgsign", "false"),
    ("gpg.format", "openpgp"),
    ("gpg.program", "gpg"),
    ("gpg.ssh.program", "ssh-keygen"),
    ("gpg.x509.program", "gpgsm"),
)
"""Signing keys aipm always sets on a commit: the user's global value, else git's default."""

AGENT_CONFIG_WATCH: tuple[str, ...] = (
    ".claude/settings.json", ".claude/settings.local.json", ".claude/CLAUDE.md",
    ".claude/hooks", ".claude/agents", ".claude/skills", ".claude/commands",
    ".codex/config.toml", ".codex/AGENTS.md", ".codex/skills",
    ".gemini/settings.json", ".gemini/GEMINI.md", ".copilot/config.json",
)  # fmt: skip
"""Agents' global settings, hooks and skills hashed before and after an attempt (SECURITY.md
§9.1). Plugin caches, which agents update on their own, are left out."""
GLOBAL_GIT_FILES: tuple[str, ...] = (".gitconfig",)
XDG_GIT_FILES: tuple[str, ...] = ("git/config", "git/attributes", "git/ignore")
MAX_INCLUDE_DEPTH = 10
"""git's own limit on nested includes."""
MAX_WATCHED_CONFIGS = 64
_KEY = re.compile(r"([A-Za-z][A-Za-z0-9-]*)\s*(?:=(.*))?", re.DOTALL)


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


def _run(
    repo: Path,
    *args: str,
    max_output: int = 1_048_576,
    timeout: float = GIT_TIMEOUT_S,
    stdin: bytes | None = None,
    env: Mapping[str, str] | None = None,
) -> ProcessResult:
    return run_safe(
        git_argv(repo, *args),
        cwd=repo,
        env=build_env(extra={**GIT_ENV, **_LITERAL, **(env or {})}),
        timeout_s=timeout,
        stdin=stdin,
        max_output_bytes=max_output,
    )


def _checked(result: ProcessResult, what: str) -> bytes:
    """stdout of a call that must succeed whole; anything else exits 2."""
    if result.returncode != 0 or result.timed_out or result.truncated:
        lines = result.stderr.decode("utf-8", errors="replace").strip().splitlines()
        detail = lines[0][:200] if lines else f"exit {result.returncode}"
        if result.truncated:
            detail = "its output was larger than aipm reads"
        raise UsageError(f"git {what} failed: {detail}")
    return result.stdout


_PROGRAM_KEY = re.compile(
    r"filter\..+\.(?:clean|smudge|process)|hook\..+\.command|trailer\..+\.(?:cmd|command)|"
    r"gpg\.ssh\.defaultkeycommand|lfs\.extension\..+\.(?:clean|smudge)|"
    r"lfs\.customtransfer\..+\.path|lfs\.standalonetransferagent|merge\..+\.driver",
    re.DOTALL,
)
"""Repository config keys that make the git commands aipm runs (or git-lfs, a global filter
they start) run a program. `merge.<name>.driver` runs when a rebase merges a file whose
attributes name it (v0.3 integrates task branches)."""
_USER_SCOPES = frozenset({b"global", b"system", b"command"})


@dataclass(frozen=True, slots=True)
class ConfigEntry:
    """One setting from the repository's own config: key as git prints it (section and name
    lower case), value, and the file it came from (`file:<path>`, relative to the repository
    for `.git/config`)."""

    key: str
    value: str
    origin: str


def repo_config_entries(repo: Path) -> list[ConfigEntry]:
    """Every setting that does not come from the user (global config, `-c`): `.git/config`,
    `config.worktree` and every file they include, as git itself reads them (`git config
    --list --show-scope --show-origin`)."""
    out = _checked(
        _run(repo, "config", "--list", "--show-scope", "--show-origin", "-z", "--includes",
             max_output=1_048_576),
        "config",
    )  # fmt: skip
    fields = _fields(out)
    if len(fields) % 3:
        raise UsageError("git config printed a list aipm cannot read")
    entries: list[ConfigEntry] = []
    for scope, origin, item in zip(fields[0::3], fields[1::3], fields[2::3], strict=True):
        if scope not in _USER_SCOPES:
            key, _, value = item.partition(b"\n")
            entries.append(ConfigEntry(*(b.decode("utf-8", errors="replace")
                                         for b in (key, value, origin))))  # fmt: skip
    return entries


MAX_SUBMODULE_DEPTH = 4
MAX_SUBMODULES = 64


def _gitlinks(repo: Path, base: str | None) -> list[str]:
    """Submodule paths git may enter: gitlinks in the index, and in `base` when given. A
    gitlink whose name aipm cannot read is refused (exit 6)."""
    out = _checked(_run(repo, "ls-files", "-s", "-z", max_output=MAX_LIST_BYTES), "ls-files")
    links: set[str] = set()
    for record in _fields(out):
        meta, _, raw = record.partition(b"\t")
        if meta.startswith(GITLINK_MODE.encode() + b" "):
            path = _decode(raw)
            if path is None:
                raise PolicyViolation("the index holds a submodule whose name aipm cannot read")
            links.add(path)
    if base is not None:
        links |= {p for p, (mode, _) in tree_entries(repo, base).items() if mode == GITLINK_MODE}
    return sorted(links)


_HINT = (
    "Move a filter driver or hook you rely on (git-lfs, git-crypt, a hook command) to your "
    "global git config (~/.gitconfig), copy included settings into .git/config, or remove the "
    "setting, then run aipm again."
)


def check_repo_config(
    repo: Path, base: str | None = None, *, depth: int = 0, top: Path | None = None
) -> None:
    """Refuse (exit 6) a repository whose own git config makes git run a program, or work on
    another directory, while aipm compares or stages files (RT02-1, ADR-0022).

    A filter driver (`filter.<name>.clean`, `smudge`, `process`) runs on every file its
    attributes name, and git-lfs (a global filter) runs `lfs.extension.<name>.clean`; a config
    hook (`hook.<name>.command`) and a trailer command run on events aipm cannot rule out on
    every git version; `gpg.ssh.defaultKeyCommand` runs when a commit is signed with SSH and no
    key is set; `core.worktree` points git at files aipm does not check. A clone never brings
    its own `.git/config`; a tarball or a copied checkout can. The user's global config is
    theirs and is not refused (hooks are still turned off).

    A config file git reads from inside the work tree (an include, a submodule's git dir that
    is not under `.git/modules/`) is refused too: a gate's child that outlives the gate could
    rewrite it between this check and git's use (residual risk R-14).

    git runs `git status` inside every populated submodule to see whether it is dirty, and that
    process reads the submodule's own config, so each submodule git may enter (the index's
    gitlinks, and `base`'s) is checked the same way. More than `MAX_SUBMODULES` populated
    submodules, or nesting deeper than `MAX_SUBMODULE_DEPTH`, is refused, never skipped.
    """
    top = repo if top is None else top
    top_dirs = git_dirs(top)
    top_git = top / ".git"
    if top_dirs.dotgit_file is not None and depth == 0:
        for own in (top_dirs.git_dir, top_dirs.common_dir):
            if _real_within(own, top):
                raise PolicyViolation(
                    f"the git directory of {top} ({own}) lies inside its work tree",
                    hint="A gate could rewrite it. Keep the git directory outside the work tree.",
                )
        top_git = top_dirs.common_dir
    found: list[str] = []
    for entry in repo_config_entries(repo):
        if _PROGRAM_KEY.fullmatch(entry.key):
            found.append(entry.key)
        elif entry.key == "core.worktree" and not _same_dir(
            git_dirs(repo).git_dir / entry.value, repo
        ):
            found.append(entry.key)
        elif entry.origin.startswith("file:"):
            source = repo / entry.origin.removeprefix("file:")
            if _real_within(source, top) and not _real_within(source, top_git):
                found.append(f"config read from the work tree ({entry.origin[5:200]})")
    where = "the repository's own git config" if depth == 0 else f"the git config of {repo}"
    if found:
        names = ", ".join(sorted(set(found))[:5])
        raise PolicyViolation(
            f"{where} sets {names}, which would make git run a program, or read another work "
            "tree, outside aipm's checks and sandbox",
            hint=_HINT,
        )
    populated = [p for p in _gitlinks(repo, base) if os.path.lexists(repo / p / ".git")]
    if len(populated) > MAX_SUBMODULES or (populated and depth >= MAX_SUBMODULE_DEPTH):
        raise PolicyViolation(
            f"{where} has more populated submodules, or deeper ones, than aipm checks "
            f"({MAX_SUBMODULES}, {MAX_SUBMODULE_DEPTH} deep)",
            hint="Deinitialize the submodules the task does not need (`git submodule deinit`).",
        )
    for path in populated:
        sub_dir = git_dirs(repo / path).git_dir
        if _real_within(sub_dir, top) and not _real_within(sub_dir, top_git):
            raise PolicyViolation(
                f"the submodule {path} keeps its git directory inside the work tree",
                hint="Move it under .git/modules with `git submodule absorbgitdirs`.",
            )
        check_repo_config(repo / path, depth=depth + 1, top=top)


def _real_within(path: Path, root: Path) -> bool:
    """Whether `path`, every link resolved, is `root` or lies under it (resolved too)."""
    real, base = os.path.realpath(path), os.path.realpath(root)
    return real == base or real.startswith(base.rstrip(os.sep) + os.sep)


def _same_dir(path: Path, repo: Path) -> bool:
    try:
        return path.samefile(repo)
    except OSError:
        return False


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


def resolve_commit(repo: Path, rev: str) -> str:
    """The full commit id for `rev`: 7 to 64 lowercase hex characters (`--base`), or `HEAD`."""
    if rev == "HEAD":
        return head_sha(repo)
    if not _REV.fullmatch(rev):
        raise UsageError(f"{rev[:80]!r} is not a commit id (7 to 64 lowercase hex characters)")
    result = _run(repo, "rev-parse", "--verify", "--quiet", f"{rev}^{{commit}}", max_output=4096)
    sha = result.stdout.decode("ascii", errors="replace").strip()
    if result.returncode != 0 or not _SHA.fullmatch(sha):
        raise UsageError(f"{rev} is not a commit in this repository")
    return sha


# ---------------------------------------------------------------- listings


def _decode(raw: bytes) -> str | None:
    """A path git printed, or `None` if it is not UTF-8 or not a plain relative path."""
    try:
        path = raw.decode("utf-8")
    except UnicodeDecodeError:
        return None
    parts = path.split("/")
    if not path or path.startswith("/") or any(p in ("", ".", "..") for p in parts[:-1]):
        return None
    if parts[-1] in (".", ".."):
        return None
    return path


def _fields(data: bytes) -> list[bytes]:
    items = data.split(b"\0")
    return items[:-1] if items and items[-1] == b"" else items


@dataclass(frozen=True, slots=True)
class StatusEntry:
    """One record of `git status --porcelain=v2 -z`.

    `kind` is `changed`, `unmerged`, `untracked` or `ignored`; `xy` the two status letters;
    `modes` the HEAD, index and work-tree modes of a changed entry. `path` is `None` when git
    printed a name aipm does not accept (not UTF-8, or not a plain relative path).
    """

    kind: str
    path: str | None
    xy: str = ""
    modes: tuple[str, ...] = ()


def parse_status_v2(data: bytes) -> list[StatusEntry]:
    """Parse `git status --porcelain=v2 -z --no-renames` output."""
    entries: list[StatusEntry] = []
    for record in _fields(data):
        tag, _, rest = record.partition(b" ")
        if tag == b"1":
            parts = rest.split(b" ", 7)
            if len(parts) != 8:
                raise UsageError("git status printed a record aipm cannot read")
            modes = tuple(p.decode("ascii", errors="replace") for p in parts[2:5])
            entries.append(StatusEntry("changed", _decode(parts[7]), parts[0].decode(), modes))
        elif tag == b"u":
            parts = rest.split(b" ", 9)
            if len(parts) != 10:
                raise UsageError("git status printed a record aipm cannot read")
            entries.append(StatusEntry("unmerged", _decode(parts[9]), parts[0].decode()))
        elif tag == b"?":
            entries.append(StatusEntry("untracked", _decode(rest)))
        elif tag == b"!":
            entries.append(StatusEntry("ignored", _decode(rest)))
        else:
            raise UsageError("git status printed a record aipm cannot read (renames are off)")
    return entries


def status_porcelain_v2(repo: Path) -> list[StatusEntry]:
    """`git status --porcelain=v2 -z`, untracked files listed one by one, no rename detection."""
    check_repo_config(repo)
    out = _checked(
        _run(repo, "status", "--porcelain=v2", "-z", "--untracked-files=all", "--no-renames",
             "--ignore-submodules=none", max_output=MAX_LIST_BYTES),
        "status",
    )  # fmt: skip
    return parse_status_v2(out)


_LETTERS = {
    "A": ChangeStatus.ADDED,
    "D": ChangeStatus.DELETED,
    "T": ChangeStatus.TYPE_CHANGED,
}


def parse_name_status(data: bytes) -> list[tuple[ChangeStatus, str | None]]:
    """Parse `git diff --name-status -z --no-renames` output."""
    fields = _fields(data)
    if len(fields) % 2:
        raise UsageError("git diff printed a list aipm cannot read")
    return [
        (_LETTERS.get(fields[i].decode("ascii", errors="replace")[:1], ChangeStatus.MODIFIED),
         _decode(fields[i + 1]))
        for i in range(0, len(fields), 2)
    ]  # fmt: skip


@contextmanager
def base_index(repo: Path, base: str) -> Generator[dict[str, str]]:
    """A fresh index holding exactly the tree of `base`, in a private temp dir.

    Change sets never trust the user's own index, where an agent can flag a changed file
    assume-unchanged or skip-worktree to hide it (step 06 security review). Yields the
    environment that points git at it (`GIT_INDEX_FILE`).
    """
    tmp = Path(tempfile.mkdtemp(prefix="aipm-index-"))
    try:
        if is_within(tmp, repo):
            raise PolicyViolation(
                "the temporary directory is inside the repository", hint="Check TMPDIR."
            )
        env = {"GIT_INDEX_FILE": str(tmp / "index")}
        _checked(_run(repo, "read-tree", base, env=env, max_output=65_536), "read-tree")
        yield env
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


def diff_names(
    repo: Path, base: str, *, env: Mapping[str, str] | None = None
) -> list[tuple[ChangeStatus, str | None]]:
    """Tracked paths that differ between `base` and the work tree."""
    out = _checked(
        _run(repo, "diff", *_DIFF_FLAGS, "--name-status", "-z", base, "--",
             max_output=MAX_LIST_BYTES, env=env),
        "diff",
    )  # fmt: skip
    return parse_name_status(out)


@dataclass(frozen=True, slots=True)
class DiffStat:
    """Lines added and deleted in one path; `None` for a binary file."""

    path: str | None
    added: int | None
    deleted: int | None


def parse_numstat(data: bytes) -> list[DiffStat]:
    """Parse `git diff --numstat -z --no-renames` output."""
    stats: list[DiffStat] = []
    for record in _fields(data):
        parts = record.split(b"\t", 2)
        if len(parts) != 3:
            raise UsageError("git diff printed a line aipm cannot read")
        counts = [int(p) if p.isdigit() else None for p in parts[:2]]
        stats.append(DiffStat(_decode(parts[2]), counts[0], counts[1]))
    return stats


def diff_stats(repo: Path, base: str) -> list[DiffStat]:
    """Lines added and deleted per tracked path between `base` and the work tree."""
    check_repo_config(repo, base)
    out = _checked(
        _run(repo, "diff", *_DIFF_FLAGS, "--numstat", "-z", base, "--",
             max_output=MAX_LIST_BYTES),
        "diff",
    )  # fmt: skip
    return parse_numstat(out)


def diff_text(repo: Path, base: str, paths: Sequence[str], *, max_bytes: int) -> tuple[str, bool]:
    """The unified diff of `paths` from `base` to the work tree (T2), and whether it was cut."""
    if not paths:
        return "", False
    check_repo_config(repo, base)
    with base_index(repo, base) as env:
        result = _run(repo, "diff", *_DIFF_FLAGS, "--no-color", base, "--", *paths,
                      max_output=max_bytes, env=env)  # fmt: skip
    if result.returncode != 0 or result.timed_out:
        raise UsageError("git diff failed")
    return result.stdout.decode("utf-8", errors="replace"), result.truncated


def untracked(repo: Path, *, env: Mapping[str, str] | None = None) -> list[str | None]:
    """Untracked files that are not ignored, one by one."""
    out = _checked(
        _run(repo, "ls-files", "-z", "--others", "--exclude-standard",
             max_output=MAX_LIST_BYTES, env=env),
        "ls-files",
    )  # fmt: skip
    return [_decode(item) for item in _fields(out)]


def ignored(repo: Path, *, env: Mapping[str, str] | None = None) -> list[str | None]:
    """Ignored files; an ignored directory is listed once, with a trailing `/`, not entered."""
    out = _checked(
        _run(repo, "ls-files", "-z", "--others", "--ignored", "--exclude-standard",
             "--directory", max_output=MAX_LIST_BYTES, env=env),
        "ls-files",
    )  # fmt: skip
    return [_decode(item) for item in _fields(out)]


def repo_files(repo: Path) -> list[str | None]:
    """Every tracked file and every untracked file that is not ignored (`aipm scan`)."""
    out = _checked(
        _run(repo, "ls-files", "-z", "--cached", "--others", "--exclude-standard",
             max_output=MAX_LIST_BYTES),
        "ls-files",
    )  # fmt: skip
    return [p for p in map(_decode, _fields(out)) if not _bytecode(p)]


def tree_entries(repo: Path, rev: str) -> dict[str, tuple[str, str]]:
    """Every file of the commit `rev`: path → (mode, object id). Reads objects only."""
    out = _checked(
        _run(repo, "ls-tree", "-r", "-z", "--full-tree", rev, max_output=MAX_LIST_BYTES),
        "ls-tree",
    )
    entries: dict[str, tuple[str, str]] = {}
    for record in _fields(out):
        meta, _, raw_path = record.partition(b"\t")
        parts = meta.split(b" ")
        path = _decode(raw_path)
        if len(parts) != 3 or path is None:
            raise UsageError("git ls-tree printed an entry aipm cannot read")
        entries[path] = (parts[0].decode("ascii"), parts[2].decode("ascii"))
    return entries


def read_object(repo: Path, object_id: str, *, max_bytes: int) -> tuple[bytes, bool]:
    """A blob's bytes, without filters or textconv, and whether it was cut at `max_bytes`."""
    if not _SHA.fullmatch(object_id):
        raise UsageError("not an object id")
    result = _run(repo, "cat-file", "blob", object_id, max_output=max_bytes)
    if result.returncode != 0 or result.timed_out:
        raise UsageError("git cat-file failed")
    return result.stdout, result.truncated


def file_at(repo: Path, rev: str, path: str, *, max_bytes: int = MAX_CONTENT_BYTES) -> bytes | None:
    """The bytes of `path` in the commit `rev`, or `None` when it has no such file."""
    entry = tree_entries(repo, resolve_commit(repo, rev)).get(path)
    if entry is None or entry[0] == GITLINK_MODE:
        return None
    return read_object(repo, entry[1], max_bytes=max_bytes)[0]


# ---------------------------------------------------------------- commits


def _global_config(repo: Path, key: str) -> str | None:
    result = _run(repo, "config", "--global", "--get", key, max_output=8192)
    if result.returncode != 0 or result.truncated:
        return None
    value = result.stdout.decode("utf-8", errors="replace").rstrip("\n")
    return value if value and "\n" not in value and "\0" not in value else None


def signing_overrides(repo: Path) -> list[str]:
    """`-c key=value` for each signing key, from the user's global config (SECURITY.md §11)."""
    options: list[str] = []
    for key, default in SIGNING_DEFAULTS:
        options += ["-c", f"{key}={_global_config(repo, key) or default}"]
    return options


def commit(
    repo: Path, paths: Sequence[str], *, message: str, trailers: Sequence[tuple[str, str]]
) -> str:
    """Commit exactly `paths` (added, changed or removed) with trailers; returns the new HEAD.

    Hooks never run: `core.hooksPath=/dev/null` and `--no-verify`. Other staged changes stay
    staged and out of the commit.
    """
    if not paths:
        raise UsageError("there is nothing to commit")
    for key, value in trailers:
        if not re.fullmatch(r"[A-Za-z][A-Za-z0-9\-]{0,40}", key) or "\n" in value:
            raise UsageError(f"not a commit trailer: {key!r}")
    check_repo_config(repo)
    signing = signing_overrides(repo)
    _checked(_run(repo, "add", "-A", "--", *paths, max_output=65_536), "add")
    body = message.strip() + "\n\n" + "".join(f"{k}: {v}\n" for k, v in trailers)
    result = _run(
        repo,
        *signing,
        "commit",
        "--no-verify",
        "--quiet",
        "--no-edit",
        "-F",
        "-",
        "--",
        *paths,
        stdin=body.encode("utf-8"),
        timeout=COMMIT_TIMEOUT_S,
        max_output=65_536,
    )
    _checked(result, "commit")
    return head_sha(repo)


type StagedId = tuple[str, str] | None
"""`("file" or "link", object id)`, or `None` for a path with nothing there."""


def _hash_object(repo: Path, *args: str, stdin: bytes | None = None) -> list[str]:
    out = _checked(_run(repo, "hash-object", *args, stdin=stdin, max_output=1_048_576),
                   "hash-object")  # fmt: skip
    ids = out.decode("ascii", errors="replace").split()
    if not all(_SHA.fullmatch(i) for i in ids):
        raise UsageError("git hash-object printed something aipm cannot read")
    return ids


def _exec_bits(repo: Path) -> bool:
    """Whether git records the executable bit here (`core.fileMode`, true unless set false)."""
    result = _run(repo, "config", "--bool", "--get", "core.filemode", max_output=64)
    return result.stdout.strip() != b"false"


def staged_ids(repo: Path, paths: Sequence[str]) -> dict[str, StagedId]:
    """What `git add` would store for each path right now, through the same attributes and
    filters (RT02-8): taken before the gates run, compared with the commit afterwards. The kind
    is `file`, `exec` (when git records the executable bit), `link` or `gitlink` (a submodule,
    whose id is its checked-out commit)."""
    ids: dict[str, StagedId] = {}
    plain: list[str] = []
    exec_bits = _exec_bits(repo)
    check_repo_config(repo)
    for path in paths:
        full = repo / path
        try:
            info = os.lstat(full)
        except FileNotFoundError:
            ids[path] = None
            continue
        if stat.S_ISLNK(info.st_mode):
            target = os.fsencode(full.readlink())
            ids[path] = ("link", _hash_object(repo, "--stdin", "--no-filters", stdin=target)[0])
        elif stat.S_ISREG(info.st_mode):
            plain.append(path)
            kind = "exec" if exec_bits and info.st_mode & stat.S_IXUSR else "file"
            ids[path] = (kind, "")
        elif stat.S_ISDIR(info.st_mode) and os.path.lexists(full / ".git"):
            try:
                ids[path] = ("gitlink", head_sha(full))
            except UsageError:  # a nested repository with no commit: nothing to compare
                pass
    # `--stdin-paths` reads one path per line and C-unquotes a line that starts with `"`.
    lined = [p for p in plain if "\n" not in p and "\r" not in p and not p.startswith('"')]
    if lined:
        found = _hash_object(repo, "--stdin-paths", stdin="".join(f"{p}\n" for p in lined).encode())
        if len(found) != len(lined):
            raise UsageError("git hash-object did not hash every file")
        for path, oid in zip(lined, found, strict=True):
            ids[path] = (_kind(ids[path]), oid)
    for path in plain:
        if path not in lined:
            ids[path] = (_kind(ids[path]), _hash_object(repo, "--", path)[0])
    return ids


def _kind(staged: StagedId) -> str:
    return "file" if staged is None else staged[0]


def committed_ids(repo: Path, rev: str, paths: Sequence[str]) -> dict[str, StagedId]:
    """What the commit `rev` holds at each path, in the form `staged_ids` gives."""
    entries = tree_entries(repo, rev)
    exec_bits = _exec_bits(repo)
    kinds = {SYMLINK_MODE: "link", GITLINK_MODE: "gitlink", "100644": "file",
             "100755": "exec" if exec_bits else "file"}  # fmt: skip
    ids: dict[str, StagedId] = {}
    for path in paths:
        entry = entries.get(path.rstrip("/"))  # an untracked nested repository is listed as `dir/`
        ids[path] = None if entry is None else (kinds.get(entry[0], entry[0]), entry[1])
    return ids


# ---------------------------------------------------------------- hashing and integrity


class _Digest(Protocol):
    def update(self, data: bytes, /) -> None: ...


def hash_path(path: Path) -> str | None:
    """A sha256 of what is at `path` without following links: a file's bytes and executable
    bit, a link's text, a directory's entries (bounded). `None` when nothing is there."""
    try:
        info = os.lstat(path)
    except FileNotFoundError:
        return None
    except OSError as exc:
        return hashlib.sha256(f"unreadable\0{exc.errno}".encode()).hexdigest()
    return _hash_entry(path, info, depth=0, budget=[MAX_TREE_ENTRIES])


def content_sha256(path: Path) -> str | None:
    """The plain sha256 of a regular file's bytes, as the `.pm/` write ledger records them.

    `None` when nothing is there; a link or anything but a regular file never matches a ledger
    entry, so it gets a value no file's bytes can have.
    """
    try:
        info = os.lstat(path)
    except FileNotFoundError:
        return None
    if not stat.S_ISREG(info.st_mode):
        return "not a regular file"
    digest = hashlib.sha256()
    _hash_file(path, digest, info.st_size)
    return digest.hexdigest()


def _ledger_has(ledger: Mapping[str, str | None], repo: Path, path: str) -> bool:
    """Whether aipm's last write to `path` (a `.pm/` file) is what is there now."""
    return path in ledger and ledger[path] == content_sha256(repo / path)


def _hash_entry(path: Path, info: os.stat_result, *, depth: int, budget: list[int]) -> str:
    digest = hashlib.sha256()
    if stat.S_ISLNK(info.st_mode):
        digest.update(b"link\0" + os.fsencode(path.readlink()))
    elif stat.S_ISREG(info.st_mode):
        digest.update(b"file\0" + (b"x" if info.st_mode & 0o111 else b"-") + b"\0")
        _hash_file(path, digest, info.st_size)
    elif stat.S_ISDIR(info.st_mode):
        digest.update(b"dir\0")
        _hash_dir(path, digest, depth=depth, budget=budget)
    else:
        digest.update(b"other\0" + str(stat.S_IFMT(info.st_mode)).encode())
    return digest.hexdigest()


def _hash_file(path: Path, digest: "_Digest", size: int) -> None:
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    except OSError as exc:
        digest.update(f"unreadable\0{exc.errno}".encode())
        return
    if not stat.S_ISREG(os.fstat(fd).st_mode):
        os.close(fd)
        digest.update(b"changed type while read")
        return
    with os.fdopen(fd, "rb") as handle:
        left = MAX_HASH_BYTES
        while left > 0:
            chunk = handle.read(min(_CHUNK, left))
            if not chunk:
                break
            digest.update(chunk)
            left -= len(chunk)
    if size > MAX_HASH_BYTES:
        digest.update(f"\0size\0{size}".encode())


def _hash_dir(path: Path, digest: "_Digest", *, depth: int, budget: list[int]) -> None:
    if depth > 8:
        digest.update(b"too deep")
        return
    try:
        entries = sorted(os.scandir(path), key=lambda e: e.name)
    except OSError as exc:
        digest.update(f"unreadable\0{exc.errno}".encode())
        return
    for entry in entries:
        budget[0] -= 1
        if budget[0] < 0:
            digest.update(b"too many entries")
            return
        info = entry.stat(follow_symlinks=False)
        child = _hash_entry(Path(entry.path), info, depth=depth + 1, budget=budget)
        digest.update(os.fsencode(entry.name) + b"\0" + child.encode() + b"\n")


@dataclass(frozen=True, slots=True)
class GitDirs:
    """Where a work tree keeps its git data: its own git dir, the shared one, and its `.git`
    file when it is a linked work tree."""

    git_dir: Path
    common_dir: Path
    dotgit_file: Path | None


def git_dirs(repo: Path) -> GitDirs:
    """Find the git directories by reading `.git`, without running git."""
    dotgit = repo / ".git"
    try:
        info = os.lstat(dotgit)
    except FileNotFoundError:
        raise UsageError(f"{repo} is not a git work tree") from None
    if stat.S_ISDIR(info.st_mode):
        return GitDirs(dotgit, dotgit, None)
    if not stat.S_ISREG(info.st_mode):
        raise PolicyViolation(f"{dotgit} is neither a directory nor a regular file")
    text = dotgit.read_text(encoding="utf-8", errors="replace")[:4096].strip()
    if not text.startswith("gitdir:"):
        raise UsageError(f"{dotgit} does not name a git directory")
    git_dir = Path(os.path.normpath(repo / text.removeprefix("gitdir:").strip()))
    common = git_dir
    commondir = git_dir / "commondir"
    if commondir.is_file():
        rel = commondir.read_text(encoding="utf-8", errors="replace")[:4096].strip()
        common = Path(os.path.normpath(git_dir / rel))
    return GitDirs(git_dir, common, dotgit)


def _read_config(path: Path) -> str:
    """A config file's text, or "" when it is not a regular file aipm can read now (never
    blocks on a FIFO)."""
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NONBLOCK)
    except OSError:
        return ""
    with os.fdopen(fd, "rb") as handle:
        if not stat.S_ISREG(os.fstat(handle.fileno()).st_mode):
            return ""
        return handle.read(1_048_576).decode("utf-8", errors="replace")


def _continues(line: str) -> bool:
    """Whether git reads past the end of `line`: an odd backslash run ends it outside a
    comment (a comment always ends at the newline)."""
    quoted = False
    index = 0
    while index < len(line):
        char = line[index]
        if char == "\\":
            if index + 1 == len(line):
                return True
            index += 2
            continue
        if char == '"':
            quoted = not quoted
        elif char in "#;" and not quoted:
            return False
        index += 1
    return False


def _logical_lines(text: str) -> list[str]:
    """Lines with git's backslash-newline continuations joined."""
    lines: list[str] = []
    pending = ""
    for raw in text.split("\n"):  # git ends a line only at "\n", never at \x0c or \x85
        line = raw.removesuffix("\r")
        if _continues(pending + line):
            pending += line[:-1]
            continue
        lines.append(pending + line)
        pending = ""
    if pending:
        lines.append(pending)
    return lines


def _header(line: str) -> tuple[str, str] | None:
    """`(section, rest of the line)` for a `[section ...]` line; quotes may hold a `]`."""
    quoted = False
    escaped = False
    for index, char in enumerate(line):
        if escaped:
            escaped = False
        elif char == "\\":
            escaped = True
        elif char == '"':
            quoted = not quoted
        elif char == "]" and not quoted:
            name = line[1:index].strip().split(None, 1)
            section = name[0].split(".", 1)[0].casefold() if name else ""
            return section, line[index + 1 :]
    return None


def _value(raw: str) -> str:
    """A config value as git reads it: quotes removed, escapes applied, comments cut."""
    out: list[str] = []
    quoted = False
    index = 0
    text = raw.strip()
    while index < len(text):
        char = text[index]
        if char == "\\" and index + 1 < len(text):
            nxt = text[index + 1]
            out.append({"n": "\n", "t": "\t", "b": "\b"}.get(nxt, nxt))
            index += 2
            continue
        if char == '"':
            quoted = not quoted
        elif char in "#;" and not quoted:
            break
        else:
            out.append(char)
        index += 1
    return "".join(out).strip() if not quoted else "".join(out)


def config_values(text: str) -> list[tuple[str, str, str]]:
    """`(section, name, value)` for every `name = value` in a git config file, the section and
    name folded to lower case as git compares them. A `[section]` header may share its line
    with a setting."""
    found: list[tuple[str, str, str]] = []
    section = ""
    for line in _logical_lines(text.removeprefix("\ufeff")):
        rest = line.strip()
        if rest.startswith("["):
            parsed = _header(rest)
            if parsed is None:
                continue
            section, rest = parsed[0], parsed[1].strip()
        if not rest or rest[0] in "#;":
            continue
        match = _KEY.fullmatch(rest)
        if match is not None:
            found.append((section, match.group(1).casefold(), _value(match.group(2) or "")))
    return found


def _expand(value: str, base: Path, home: Path) -> Path | None:
    """A path setting as git resolves it: `~/` from home, relative to `base`."""
    if not value or value.startswith("%(prefix)"):
        return None
    if value == "~" or value.startswith("~/"):
        return home / value[2:]
    if value.startswith("~"):
        expanded = Path(value).expanduser()
        return expanded if expanded.is_absolute() else None
    path = Path(value)
    return path if path.is_absolute() else base / path


def config_paths(configs: Sequence[Path], home: Path, repo: Path) -> dict[str, Path]:
    """Every file the configs include, nested as deep as git follows them, and every
    `core.excludesFile` and `core.attributesFile` they name (red-team v0.2, RT02-7)."""
    found: dict[str, Path] = {}
    queue = [(config, 0) for config in configs]
    seen: set[Path] = set()
    while queue:
        config, depth = queue.pop(0)
        if config in seen:
            continue
        if len(seen) >= MAX_WATCHED_CONFIGS:
            raise PolicyViolation(
                f"git's config files include more than {MAX_WATCHED_CONFIGS} files, more "
                "than aipm watches",
                hint="Reduce the [include] chain in your git config.",
            )
        seen.add(config)
        for section, name, value in config_values(_read_config(config)):
            if section in ("include", "includeif") and name == "path":
                target = _expand(value, config.parent, home)
                if target is not None:
                    found[f"include: {target}"] = target
                    if depth < MAX_INCLUDE_DEPTH:
                        queue.append((target, depth + 1))
            elif section == "core" and name in ("excludesfile", "attributesfile"):
                target = _expand(value, repo, home)
                if target is not None:
                    found[f"core.{name}: {target}"] = target
    return found


def integrity_snapshot(repo: Path, home: Path) -> dict[str, str | None]:
    """Hashes of what git and the agents read from outside the work tree (SECURITY.md §11).

    `.git/config`, `config.worktree`, `info/attributes`, `info/exclude`, `hooks/`, the linked
    work tree's `.git` file, files those configs include (nested), the excludes and attributes
    files they name, the user's global git config, and the agents' global settings, hooks and
    skills. Read only; git is not run. git gets no `XDG_CONFIG_HOME` (`build_env`), so it reads
    `~/.config/git/`; when aipm's own `XDG_CONFIG_HOME` points elsewhere, both are watched.
    """
    dirs = git_dirs(repo)
    xdg = Path(os.environ.get("XDG_CONFIG_HOME") or home / ".config")
    watched: dict[str, Path] = {
        ".git/config": dirs.common_dir / "config",
        ".git/config.worktree": dirs.git_dir / "config.worktree",
        ".git/info/attributes": dirs.common_dir / "info" / "attributes",
        ".git/info/exclude": dirs.common_dir / "info" / "exclude",
        ".git/hooks": dirs.common_dir / "hooks",
        ".git/refs/replace": dirs.common_dir / "refs" / "replace",
        ".git/info/grafts": dirs.common_dir / "info" / "grafts",
        ".git/objects/info/alternates": dirs.common_dir / "objects" / "info" / "alternates",
    }
    if dirs.dotgit_file is not None:
        watched[".git (work tree file)"] = dirs.dotgit_file
    configs = [dirs.common_dir / "config", dirs.git_dir / "config.worktree"]
    for rel in GLOBAL_GIT_FILES:
        watched[f"~/{rel}"] = home / rel
        configs.append(home / rel)
    for rel in XDG_GIT_FILES:
        watched[f"$XDG_CONFIG_HOME/{rel}"] = xdg / rel
        if xdg != home / ".config":
            watched[f"~/.config/{rel}"] = home / ".config" / rel
    configs += [xdg / "git" / "config", home / ".config" / "git" / "config"]
    watched.update(config_paths(configs, home, repo))
    for rel in AGENT_CONFIG_WATCH:
        watched[f"~/{rel}"] = home / rel
    return {label: _hash_followed(path) for label, path in watched.items()}


def _hash_followed(path: Path) -> str | None:
    """`hash_path`, and for a link also what it points at: git follows a linked config file,
    so an edit to its target must show (security review of RT02-7)."""
    digest = hash_path(path)
    if digest is None or not path.is_symlink():
        return digest
    target = hash_path(Path(os.path.realpath(path)))
    return hashlib.sha256(f"{digest}\0{target}".encode()).hexdigest()


def compare(before: Mapping[str, str | None], after: Mapping[str, str | None]) -> list[str]:
    """The labels whose hash differs, or that only one side has."""
    return sorted(k for k in set(before) | set(after) if before.get(k) != after.get(k))


# ---------------------------------------------------------------- snapshots and change sets


@dataclass(frozen=True, slots=True)
class Listing:
    """The files git sees outside `base`: changed tracked ones, untracked and ignored ones."""

    tracked: list[tuple[ChangeStatus, str | None]]
    untracked: list[str | None]
    ignored_files: list[str | None]


def _bytecode(path: str | None) -> bool:
    """A Python bytecode cache: gates neither write nor read these in the tree
    (`PYTHONPYCACHEPREFIX`), so they are left out of snapshots and change sets."""
    return path is not None and ("__pycache__" in path.split("/") or path.endswith(".pyc"))


def listing(repo: Path, base: str) -> Listing:
    """Tracked changes since `base`, untracked files, and ignored files (not directories),
    all against a fresh index of `base`, never the user's own index. A repository whose own
    config names a program for git to run is refused first (`check_repo_config`)."""
    check_repo_config(repo, base)
    with base_index(repo, base) as env:
        tracked = diff_names(repo, base, env=env)
        others = untracked(repo, env=env)
        skipped = ignored(repo, env=env)
    return Listing(
        tracked=[(s, p) for s, p in tracked if not _bytecode(p)],
        untracked=[p for p in others if not _bytecode(p)],
        ignored_files=[p for p in skipped if p is None or not (p.endswith("/") or _bytecode(p))],
    )


def snapshot_files(
    repo: Path, base: str, *, watch_ignored: Callable[[str], bool]
) -> dict[str, str]:
    """Hash every file that differs from `base` or is untracked, and the ignored files that
    `watch_ignored` names (protected paths and tests), for the attempt snapshot.

    More files than aipm keeps, or a name it cannot read, exits 2: commit, remove or ignore them.
    """
    seen = listing(repo, base)
    names = [p for _, p in seen.tracked] + seen.untracked
    names += [p for p in seen.ignored_files if p is None or watch_ignored(p)]
    if any(p is None for p in names):
        raise UsageError(
            "git lists a file whose name aipm cannot read (not UTF-8, or not a plain path)",
            hint="Rename or remove it before starting the task.",
        )
    if len(names) > MAX_SNAPSHOT_FILES:
        raise UsageError(
            f"more than {MAX_SNAPSHOT_FILES} changed or untracked files",
            hint="Commit, remove or ignore them before starting the task.",
        )
    files: dict[str, str] = {}
    for name in names:
        assert name is not None  # noqa: S101 - checked above
        digest = hash_path(repo / name)
        if digest is not None:
            files[name] = digest
    return files


def _mode(info: os.stat_result) -> str:
    if stat.S_ISLNK(info.st_mode):
        return SYMLINK_MODE
    if stat.S_ISDIR(info.st_mode):
        return DIR_MODE
    if stat.S_ISREG(info.st_mode):
        return "100755" if info.st_mode & 0o111 else "100644"
    return "000000"


def _link_facts(repo: Path, path: str, patterns: Sequence[str]) -> tuple[str, bool, bool]:
    full = repo / path
    target = str(full.readlink())
    root = os.path.realpath(repo)
    real = os.path.realpath(full)
    if real == root or not real.startswith(root.rstrip(os.sep) + os.sep):
        return target, True, False
    rel = os.path.relpath(real, root).replace(os.sep, "/")
    return target, False, is_protected(rel, patterns)


def _read_now(path: Path, limit: int) -> tuple[bytes | None, bool]:
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    except OSError:
        return None, False
    if not stat.S_ISREG(os.fstat(fd).st_mode):
        os.close(fd)
        return None, False
    with os.fdopen(fd, "rb") as handle:
        data = handle.read(limit + 1)
    return data[:limit], len(data) > limit


def _is_aipm_scratch(path: str) -> bool:
    name = path.removeprefix(".pm/")
    return path == ".pm/.lock" or (path.startswith(".pm/") and ".tmp-" in name)


@dataclass(frozen=True, slots=True)
class ChangeInputs:
    """What `change_set` compares the tree with: the attempt snapshot and aipm's own writes."""

    base_sha: str
    integrity: Mapping[str, str | None]
    files: Mapping[str, str]
    ledger: Mapping[str, str | None]
    extra_protected: Sequence[str] = ()


def change_set(
    repo: Path,
    inputs: ChangeInputs,
    *,
    home: Path,
    watch_ignored: Callable[[str], bool],
    wants_content: Callable[[str], bool],
    content_limit: Callable[[str], int] | None = None,
) -> ChangeSet:
    """Everything that changed since the attempt snapshot (ARCHITECTURE §12.4 step 3.1).

    The integrity hashes are compared first; if any differs, git is not run and the change set
    holds only that. A path counts as changed when it differs from `base_sha` (or is untracked)
    and from its snapshot hash. A `.pm/` path whose hash is aipm's last write is aipm's own.
    `content_limit` says how many bytes of a path to read (`MAX_CONTENT_BYTES` unless it says
    otherwise; lockfiles need more).
    """
    base = inputs.base_sha
    moved = compare(inputs.integrity, integrity_snapshot(repo, home))
    if moved:
        return ChangeSet(base_sha=base, integrity=tuple(moved), complete=False)
    seen = listing(repo, base)
    tree = tree_entries(repo, base)
    statuses, complete = _statuses(repo, seen, tree, inputs)
    hidden, readable = _hidden(repo, seen, inputs, watch_ignored)
    complete = complete and readable
    patterns = protected_patterns(inputs.extra_protected)
    changes: list[FileChange] = []
    budget = MAX_TOTAL_CONTENT
    for path in sorted(statuses):
        now = hash_path(repo / path)
        if path in inputs.files and inputs.files[path] == now:
            continue
        if _is_aipm_scratch(path) or _ledger_has(inputs.ledger, repo, path):
            continue
        if len(changes) >= MAX_CHANGES:
            complete = False
            break
        cap = MAX_CONTENT_BYTES if content_limit is None else content_limit(path)
        change, used = _describe(
            repo, path, statuses[path], tree, patterns, min(cap, budget), wants_content
        )
        budget -= used
        changes.append(change)
    return ChangeSet(
        base_sha=base, files=tuple(changes), hidden=tuple(sorted(hidden)), complete=complete
    )


def _statuses(
    repo: Path, seen: Listing, tree: Mapping[str, tuple[str, str]], inputs: ChangeInputs
) -> tuple[dict[str, ChangeStatus], bool]:
    complete = True
    statuses: dict[str, ChangeStatus] = {}
    for status, path in seen.tracked:
        if path is None:
            complete = False
        else:
            statuses[path] = status
    for path in seen.untracked:
        if path is None:
            complete = False
        else:
            statuses[path] = ChangeStatus.MODIFIED if path in statuses else ChangeStatus.ADDED
    for path in inputs.files:
        if path not in statuses and path not in tree and not os.path.lexists(repo / path):
            statuses[path] = ChangeStatus.DELETED
    return statuses, complete


def _hidden(
    repo: Path, seen: Listing, inputs: ChangeInputs, watch_ignored: Callable[[str], bool]
) -> tuple[list[str], bool]:
    """Ignored files on a watched path whose hash is neither the snapshot's nor aipm's."""
    hidden: list[str] = []
    complete = True
    for path in seen.ignored_files:
        if path is None:
            complete = False
        elif watch_ignored(path) and not _is_aipm_scratch(path):
            if inputs.files.get(path) != hash_path(repo / path) and not _ledger_has(
                inputs.ledger, repo, path
            ):
                hidden.append(path)
    return hidden, complete


def _describe(
    repo: Path,
    path: str,
    status: ChangeStatus,
    tree: Mapping[str, tuple[str, str]],
    patterns: Sequence[str],
    budget: int,
    wants_content: Callable[[str], bool],
) -> tuple[FileChange, int]:
    base_entry = tree.get(path)
    base_mode = base_entry[0] if base_entry else None
    try:
        info: os.stat_result | None = os.lstat(repo / path)
    except FileNotFoundError:
        info = None
    if info is None:
        status = ChangeStatus.DELETED
    elif base_entry is None:
        status = ChangeStatus.ADDED
    mode = _mode(info) if info is not None else None
    if mode == DIR_MODE and base_mode == GITLINK_MODE:
        mode = GITLINK_MODE
    link_target, escapes, protected = None, False, False
    if mode == SYMLINK_MODE:
        link_target, escapes, protected = _link_facts(repo, path, patterns)
    before = after = None
    truncated = False
    used = 0
    if wants_content(path) and budget > 0:
        limit = budget
        if base_entry is not None and base_mode not in (GITLINK_MODE, SYMLINK_MODE):
            raw, cut = read_object(repo, base_entry[1], max_bytes=limit)
            before, truncated, used = raw.decode("utf-8", errors="replace"), cut, len(raw)
        if info is not None and mode not in (SYMLINK_MODE, DIR_MODE, GITLINK_MODE):
            raw_now, cut_now = _read_now(repo / path, limit)
            if raw_now is not None:
                after = raw_now.decode("utf-8", errors="replace")
                truncated = truncated or cut_now
                used += len(raw_now)
    elif wants_content(path):
        truncated = True
    change = FileChange(
        path=path,
        status=status,
        mode=mode,
        base_mode=base_mode,
        link_target=link_target,
        link_escapes=escapes,
        link_protected=protected,
        before=before,
        after=after,
        truncated=truncated,
    )
    return change, used


# ---------------------------------------------------------------- branches and worktrees (v0.3)

_BRANCH = re.compile(r"[A-Za-z0-9][A-Za-z0-9._/\-]{0,99}")
_TRAILER_TASK = re.compile(r"T-[0-9]{3}")
_TRAILER_RUN = re.compile(r"r-[0-9]{8}-[0-9]{4}-[0-9a-f]{4}")
_TRAILER_ATTEMPT = re.compile(r"[1-9][0-9]{0,2}")
TRAILER_SCAN = 2_000
"""How many commits a trailer search reads at most."""
_TRAILER_FORMAT = (
    "%H%x00%P%x00%(trailers:key=Aipm-Task,valueonly,separator=%x2C)%x00"
    "%(trailers:key=Aipm-Run,valueonly,separator=%x2C)%x00"
    "%(trailers:key=Aipm-Attempt,valueonly,separator=%x2C)%x00"
)


def check_branch(name: str) -> str:
    """`name`, if it is a branch name aipm passes to git; exit 2 otherwise.

    Letters, digits and `. _ / -`, at most 100 characters, starting with a letter or digit; no
    empty component, no component that starts with `.` or `-` or ends with `.` or `.lock`, and
    no `..`. Narrower than `git check-ref-format`, so a name can never read as an option.
    """
    parts = name.split("/")
    if (
        not _BRANCH.fullmatch(name)
        or ".." in name
        or any(not p or p.startswith((".", "-")) or p.endswith((".", ".lock")) for p in parts)
    ):
        raise UsageError(f"{name[:80]!r} is not a branch name aipm can use")
    return name


def _full_sha(value: str) -> str:
    if not _SHA.fullmatch(value):
        raise UsageError(f"{value[:80]!r} is not a full commit id")
    return value


def ref_sha(repo: Path, branch: str) -> str | None:
    """The commit `refs/heads/<branch>` points at, or `None` when there is no such branch."""
    ref = f"refs/heads/{check_branch(branch)}^{{commit}}"
    result = _run(repo, "rev-parse", "--verify", "--quiet", ref, max_output=4096)
    sha = result.stdout.decode("ascii", errors="replace").strip()
    if result.returncode == 1 and not sha and not result.timed_out:
        return None
    if result.returncode != 0 or not _SHA.fullmatch(sha):
        raise UsageError(f"git cannot read the branch {branch}")
    return sha


def is_ancestor(repo: Path, ancestor: str, descendant: str) -> bool:
    """Whether commit `ancestor` is `descendant` or one of its ancestors."""
    result = _run(
        repo, "merge-base", "--is-ancestor", _full_sha(ancestor), _full_sha(descendant),
        max_output=4096,
    )  # fmt: skip
    if result.returncode not in (0, 1) or result.timed_out:
        raise UsageError("git merge-base failed")
    return result.returncode == 0


def update_ref(repo: Path, branch: str, new: str, old: str | None) -> None:
    """Point `branch` at `new`, only if it points at `old` now (`None`: only if it does not
    exist yet). A compare-and-swap: a branch that moved under aipm is never overwritten."""
    expected = "0" * len(_full_sha(new)) if old is None else _full_sha(old)
    ref = f"refs/heads/{check_branch(branch)}"
    result = _run(repo, "update-ref", "-m", "aipm", ref, new, expected, max_output=4096)
    _checked(result, f"update-ref {branch}")


def delete_branch(repo: Path, branch: str, old: str) -> None:
    """Delete `branch`, only if it still points at `old`."""
    ref = f"refs/heads/{check_branch(branch)}"
    _checked(_run(repo, "update-ref", "-d", ref, _full_sha(old), max_output=4096), "update-ref -d")


@dataclass(frozen=True, slots=True)
class WorktreeEntry:
    """One record of `git worktree list --porcelain`; `branch` without `refs/heads/`."""

    path: str
    head: str | None
    branch: str | None


def worktrees(repo: Path) -> list[WorktreeEntry]:
    """Every worktree of the repository, the main one first."""
    out = _checked(
        _run(repo, "worktree", "list", "--porcelain", "-z", max_output=MAX_LIST_BYTES),
        "worktree list",
    )
    entries: list[WorktreeEntry] = []
    record: dict[str, str] = {}
    for field in [*out.split(b"\0"), b""]:
        if field:
            key, _, value = field.decode("utf-8", errors="replace").partition(" ")
            record[key] = value
        elif record:
            branch = record.get("branch", "")
            entries.append(
                WorktreeEntry(
                    path=record.get("worktree", ""),
                    head=record.get("HEAD"),
                    branch=branch.removeprefix("refs/heads/")
                    if branch.startswith("refs/heads/")
                    else None,
                )
            )
            record = {}
    return entries


def checked_out(repo: Path, branch: str) -> list[str]:
    """The worktrees that have `branch` checked out."""
    return [w.path for w in worktrees(repo) if w.branch == branch]


def worktree_add(repo: Path, path: Path, branch: str, start: str) -> None:
    """Check `start` out into a new worktree at `path`, on `branch`, created or reset there.

    The checkout reads the repository's attributes, so its config is checked first (ADR-0022).
    """
    check_repo_config(repo)
    result = _run(
        repo, "worktree", "add", "--quiet", "--no-track", "-B", check_branch(branch),
        str(path), _full_sha(start), timeout=COMMIT_TIMEOUT_S, max_output=65_536,
    )  # fmt: skip
    _checked(result, "worktree add")


def worktree_remove(repo: Path, path: Path) -> None:
    """Remove the worktree at `path`, changes and all, and prune git's record of any worktree
    whose directory is gone. A path git does not know is left to the caller."""
    _run(repo, "worktree", "remove", "--force", "--force", str(path),
         timeout=COMMIT_TIMEOUT_S, max_output=65_536)  # fmt: skip
    _checked(_run(repo, "worktree", "prune", max_output=65_536), "worktree prune")


def clean(wt: Path) -> None:
    """Remove every untracked and ignored file from the work tree `wt`."""
    result = _run(wt, "clean", "-f", "-f", "-d", "-x", "--quiet",
                  timeout=COMMIT_TIMEOUT_S, max_output=65_536)  # fmt: skip
    _checked(result, "clean")


def _remove_new(wt: Path, path: str) -> None:
    """Delete what `path` holds in the work tree, never following a link out of it.

    aipm runs this outside any sandbox, in a tree an agent could write, and a child the agent
    left behind could swap a directory for a link between a check and the delete (step 07
    review). So nothing is resolved through the tree: each leading directory is opened with
    `O_NOFOLLOW` relative to the one before, and the last name is removed relative to that.
    """
    parts = path.rstrip("/").split("/")
    fd = os.open(wt, os.O_RDONLY | os.O_DIRECTORY)
    try:
        for part in parts[:-1]:
            flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
            try:
                inner = os.open(part, flags, dir_fd=fd)
            except FileNotFoundError:
                return
            except OSError:  # a link or a file where a directory should be
                raise PolicyViolation(f"{path} does not lie inside the work tree") from None
            os.close(fd)
            fd = inner
        name = parts[-1]
        try:
            info = os.stat(name, dir_fd=fd, follow_symlinks=False)
        except FileNotFoundError:
            return
        if stat.S_ISDIR(info.st_mode):
            shutil.rmtree(name, dir_fd=fd)
        else:
            os.unlink(name, dir_fd=fd)
    finally:
        os.close(fd)


def restore_paths(wt: Path, base: str, paths: Sequence[str]) -> None:
    """Put each path back as the commit `base` has it: restored if `base` has it, deleted if
    not, in the work tree and the index (minor post-change violations, ARCHITECTURE §12.4)."""
    if not paths:
        return
    check_repo_config(wt)
    tree = tree_entries(wt, _full_sha(base))
    known = sorted(p for p in paths if p.rstrip("/") in tree)
    new = sorted(p for p in paths if p.rstrip("/") not in tree)
    if known:
        result = _run(wt, "restore", f"--source={base}", "--staged", "--worktree", "--", *known,
                      timeout=COMMIT_TIMEOUT_S, max_output=65_536)  # fmt: skip
        _checked(result, "restore")
    for path in new:
        _remove_new(wt, path)
    if new:
        stripped = [p.rstrip("/") for p in new]
        result = _run(wt, "rm", "--cached", "--quiet", "--ignore-unmatch", "-r", "--", *stripped,
                      max_output=65_536)  # fmt: skip
        _checked(result, "rm --cached")


def rebase_onto(wt: Path, onto: str, upstream: str) -> bool:
    """Replay the commits after `upstream` onto `onto` in the work tree `wt`.

    Returns `False` after a conflict, which is aborted. Signing follows the user's global
    config, hooks are off, and a repository merge driver was refused by `check_repo_config`.
    """
    check_repo_config(wt)
    signing = signing_overrides(wt)
    result = _run(
        wt, *signing, "rebase", "--quiet", "--no-verify", "--no-autostash", "--onto",
        _full_sha(onto), _full_sha(upstream), timeout=COMMIT_TIMEOUT_S, max_output=1_048_576,
    )  # fmt: skip
    if result.returncode == 0 and not result.timed_out:
        return True
    _run(wt, "rebase", "--abort", timeout=COMMIT_TIMEOUT_S, max_output=65_536)
    if result.returncode != 1 or result.timed_out:
        _checked(result, "rebase")
    return False


def merge_ff_only(repo: Path, sha: str) -> None:
    """Fast-forward the checked-out branch of `repo` to `sha`; refuse anything else (exit 2)."""
    check_repo_config(repo)
    result = _run(repo, "merge", "--ff-only", "--quiet", "--no-verify", _full_sha(sha),
                  timeout=COMMIT_TIMEOUT_S, max_output=65_536)  # fmt: skip
    _checked(result, "merge --ff-only")


def current_branch(repo: Path) -> str | None:
    """The branch checked out in `repo`, or `None` when HEAD is detached."""
    result = _run(repo, "symbolic-ref", "--quiet", "--short", "HEAD", max_output=4096)
    name = result.stdout.decode("utf-8", errors="replace").strip()
    return name if result.returncode == 0 and name else None


def log_oneline(repo: Path, base: str, tip: str, *, limit: int = 200) -> tuple[list[str], bool]:
    """`git log --oneline base..tip`, newest first, at most `limit` lines, and whether there
    were more. The subjects are repository text: print them only after sanitizing."""
    out = _checked(
        _run(repo, "log", "--no-show-signature", "--no-decorate", "--format=%h %s",
             f"--max-count={limit + 1}", f"{_full_sha(base)}..{_full_sha(tip)}", "--",
             max_output=1_048_576),
        "log",
    )  # fmt: skip
    lines = out.decode("utf-8", errors="replace").splitlines()
    return lines[:limit], len(lines) > limit


@dataclass(frozen=True, slots=True)
class TrailerCommit:
    """A commit with its parents and the aipm trailers it carries (`None` when absent)."""

    sha: str
    parents: tuple[str, ...]
    task: str | None
    run: str | None
    attempt: int | None


def _trailer(value: bytes, pattern: re.Pattern[str]) -> str | None:
    text = value.decode("utf-8", errors="replace").strip()
    return text if pattern.fullmatch(text) else None


def trailer_commits(
    repo: Path, tip: str, *, since: str | None = None, limit: int = TRAILER_SCAN
) -> list[TrailerCommit]:
    """The commits reachable from `tip` and not from `since`, newest first, at most `limit`,
    with their `Aipm-Task`, `Aipm-Run` and `Aipm-Attempt` trailers (ARCHITECTURE §12.6)."""
    revs = _full_sha(tip) if since is None else f"{_full_sha(since)}..{_full_sha(tip)}"
    out = _checked(
        _run(repo, "log", "--no-show-signature", f"--format={_TRAILER_FORMAT}",
             f"--max-count={limit}", revs, "--", max_output=MAX_LIST_BYTES),
        "log",
    )  # fmt: skip
    found: list[TrailerCommit] = []
    for record in out.split(b"\0\n"):
        fields = record.strip(b"\n").split(b"\0")
        if len(fields) != 5:
            continue
        sha = fields[0].decode("ascii", errors="replace")
        parents = tuple(fields[1].decode("ascii", errors="replace").split())
        if not _SHA.fullmatch(sha) or not all(_SHA.fullmatch(p) for p in parents):
            raise UsageError("git log printed a commit aipm cannot read")
        attempt = _trailer(fields[4], _TRAILER_ATTEMPT)
        found.append(
            TrailerCommit(
                sha=sha,
                parents=parents,
                task=_trailer(fields[2], _TRAILER_TASK),
                run=_trailer(fields[3], _TRAILER_RUN),
                attempt=None if attempt is None else int(attempt),
            )
        )
    return found


def changed_paths(repo: Path, a: str, b: str) -> list[str]:
    """The paths that differ between commits `a` and `b`."""
    out = _checked(
        _run(repo, "diff", *_DIFF_FLAGS, "--name-only", "-z", _full_sha(a), _full_sha(b), "--",
             max_output=MAX_LIST_BYTES),
        "diff",
    )  # fmt: skip
    paths: list[str] = []
    for raw in _fields(out):
        path = _decode(raw)
        if path is None:
            raise UsageError("git diff printed a path aipm cannot read")
        paths.append(path)
    return paths
