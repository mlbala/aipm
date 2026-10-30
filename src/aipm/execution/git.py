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
GIT_ENV: dict[str, str] = {
    "GIT_TERMINAL_PROMPT": "0",
    "GIT_OPTIONAL_LOCKS": "0",
    "GIT_CONFIG_NOSYSTEM": "1",
    "GIT_NO_REPLACE_OBJECTS": "1",
}
_LITERAL = {"GIT_LITERAL_PATHSPECS": "1"}
_SHA = re.compile(r"[0-9a-f]{40}(?:[0-9a-f]{24})?")
_REV = re.compile(r"[0-9a-f]{7,64}")
_DIFF_FLAGS = ("--no-ext-diff", "--no-textconv", "--no-renames", "--ignore-submodules=none")

MAX_LIST_BYTES = 32 * 1_048_576
MAX_CHANGES = 2_000
MAX_SNAPSHOT_FILES = 20_000
MAX_CONTENT_BYTES = 262_144
MAX_TOTAL_CONTENT = 8 * 1_048_576
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
_INCLUDE = re.compile(r"^\s*path\s*=\s*(.+?)\s*$")
_SECTION = re.compile(r"^\s*\[\s*([A-Za-z]+)")


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


def _include_paths(config: Path, home: Path) -> list[Path]:
    """Files a git config names in `[include]` and `[includeIf]` sections (one level)."""
    try:
        lines = config.read_text(encoding="utf-8", errors="replace")[:1_048_576].splitlines()
    except OSError:
        return []
    found: list[Path] = []
    section = ""
    for line in lines:
        head = _SECTION.match(line)
        if head is not None:
            section = head.group(1).casefold()
            continue
        match = _INCLUDE.match(line)
        if section in ("include", "includeif") and match is not None:
            value = match.group(1).strip('"')
            target = home / value[2:] if value.startswith("~/") else Path(value)
            found.append(target if target.is_absolute() else config.parent / target)
    return found[:32]


def integrity_snapshot(repo: Path, home: Path) -> dict[str, str | None]:
    """Hashes of what git and the agents read from outside the work tree (SECURITY.md §11).

    `.git/config`, `config.worktree`, `info/attributes`, `info/exclude`, `hooks/`, the linked
    work tree's `.git` file, files those configs include, the user's global git config, and the
    agents' global settings, hooks and skills. Read only; git is not run.
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
    configs.append(xdg / "git" / "config")
    for config in configs:
        for included in _include_paths(config, home):
            watched[f"include: {included}"] = included
    for rel in AGENT_CONFIG_WATCH:
        watched[f"~/{rel}"] = home / rel
    return {label: hash_path(path) for label, path in watched.items()}


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
    all against a fresh index of `base`, never the user's own index."""
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
) -> ChangeSet:
    """Everything that changed since the attempt snapshot (ARCHITECTURE §12.4 step 3.1).

    The integrity hashes are compared first; if any differs, git is not run and the change set
    holds only that. A path counts as changed when it differs from `base_sha` (or is untracked)
    and from its snapshot hash. A `.pm/` path whose hash is aipm's last write is aipm's own.
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
        change, used = _describe(repo, path, statuses[path], tree, patterns, budget, wants_content)
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
        limit = min(MAX_CONTENT_BYTES, budget)
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
