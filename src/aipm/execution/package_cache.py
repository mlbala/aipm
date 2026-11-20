"""A package cache for each run, shared by the run's tasks and deleted when the run ends (v0.2
O-2, ADR-0031).

The prepare step runs repository code (a build backend, `setup.py`), and it used to write the
user's own package caches (`~/.cache/uv`, `~/.npm`, ...), which every other project on the
machine reads outside any sandbox (R-13). Now each package manager is pointed, through its own
environment variable, at a directory of the run under aipm's cache, and only that directory is
writable for prepare under `srt`. Gates read it (Go and Cargo work offline from what prepare
fetched) but never write it. Go's build cache is per attempt, in the attempt's temp dir.

Within one run the tasks share the cache, so one task's prepare can affect what a later task's
prepare reads: the owner's choice of a per-run cache over a per-attempt one (ADR-0031). What
Cargo would run from it (`$CARGO_HOME/bin/cargo-<cmd>`, before PATH) or read as settings
(`$CARGO_HOME/config.toml`) is write-denied to every process (`sandbox.PROTECTED_CARGO`).
"""

import os
import re
import shutil
import stat
from contextlib import suppress
from pathlib import Path

from aipm.domain.errors import UsageError
from aipm.execution.sandbox import CARGO_DIR, CARGO_LOCK_FILES, PREPARE_WRITABLE
from aipm.execution.worktree import cache_root, outside_repo
from aipm.security.command_policy import program_name
from aipm.state.layout import repo_id

PACKAGES_DIR = "packages"
_RUN_ID = re.compile(r"r-\d{8}-\d{4}-[0-9a-f]{4}")
MAX_CARGO_CONFIG_BYTES = 1_048_576

_CACHE_ENV: dict[str, tuple[tuple[str, str], ...]] = {
    "uv": (("UV_CACHE_DIR", "uv"),),
    "python": (("PIP_CACHE_DIR", "pip"),),
    "pip": (("PIP_CACHE_DIR", "pip"),),
    "npm": (("npm_config_cache", "npm"),),
    "pnpm": (("npm_config_store_dir", "pnpm-store"), ("npm_config_cache_dir", "pnpm-cache")),
    "go": (("GOMODCACHE", "go-mod"),),
    "gotestsum": (("GOMODCACHE", "go-mod"),),
    "cargo": (("CARGO_HOME", "cargo"),),
}
"""For each program: the variable that moves its package cache, and the directory in the run's
cache it moves to."""

_COPY_ENV: dict[str, dict[str, str]] = {
    "uv": {"UV_LINK_MODE": "copy"},
    "pnpm": {"npm_config_package_import_method": "clone-or-copy"},
}
"""Install copies (or copy-on-write clones), never hard links: on Linux uv and pnpm hard-link
from their cache by default, so a write to the worktree's `.venv` or `node_modules`, which the
agent and the gates may make, would change the run's cache for the next task (security review
of the v0.4 decisions)."""


def cache_args(program: str, cache: Path) -> tuple[str, ...]:
    """Options that prepare puts right after `program`, before its subcommand. pnpm 10 lets a
    committed `pnpm-workspace.yaml` override the store and import method `cache_env` sets, but
    not its own flags, so a repository's `packageImportMethod: hardlink` could make every task's
    `node_modules` share files with the run's store (security review of the v0.4 decisions,
    session 3). `copy`, not `clone-or-copy`: pnpm 10.34.9 ignored a `clone-or-copy` flag that
    repeated the environment's value, and the file's setting won. pnpm 10.34.9 accepts them
    before `install`, `fetch` and `test`, and refuses them ("Unknown options") before `run`,
    `exec` and `rebuild`, so a prepare step of that kind fails closed and gates get none
    (session 3 re-review). The file's `cacheDir`, `virtualStoreDir` and `modulesDir` could move
    pnpm's metadata cache, its virtual store or `node_modules` itself outside the worktree; the
    flags keep them in the run's cache and the worktree (session 4; checked by hand on 10.34.9:
    without the flag a committed `virtualStoreDir` was used, with it the worktree's)."""
    if program_name(program) != "pnpm":
        return ()
    return (
        f"--store-dir={cache / 'pnpm-store'}",
        "--package-import-method=copy",
        f"--cache-dir={cache / 'pnpm-cache'}",
        "--virtual-store-dir=node_modules/.pnpm",
        "--modules-dir=node_modules",
    )


def lockfile_args(program: str) -> tuple[str, ...]:
    """The option that prepare puts after `cache_args`: pnpm's lockfile directory is `.`, the
    worktree root prepare runs in. A committed `lockfile-dir` (in `.npmrc`, `pnpm-workspace.yaml`'s
    `lockfileDir`, or the `.npmrc` of the directory a `pnpm -C <dir>` names) moved the lockfile
    and the virtual store, which the relative `--virtual-store-dir` resolves against, outside
    the worktree, so every task's `node_modules` could link into one store there (v0.4
    decisions, session 5, item 2 review). Checked by hand on pnpm 10.34.9: the flag beats all
    three; `npm_config_lockfile_dir` beats only the `.npmrc` ones. Relative, not the absolute
    root: pnpm resolves it against its working directory also under `-C <dir>`, and an absolute
    path would put the user's checkout path (in `verify`) into argv, which `srt` refuses when
    it holds a quote or `$` (`sandbox.check_shell_safe`; session 5, item 2 re-review). A
    repository with one lockfile per project (`sharedWorkspaceLockfile: false`) fails a
    `--frozen-lockfile` prepare: it must use one shared lockfile."""
    if program_name(program) != "pnpm":
        return ()
    return ("--lockfile-dir=.",)


def pnpm_env(program: str, root: Path) -> dict[str, str]:
    """The variables that keep pnpm to the worktree and to what prepare installed, when
    `program` is pnpm itself; `pnpm_guard_env` gives them to every other program too (v0.4
    decisions, session 4; each checked by hand on pnpm 10.34.9).

    - `NPM_CONFIG_WORKSPACE_DIR`: pnpm looks for `pnpm-workspace.yaml` in every directory above
      its working directory; pinned to the worktree, a file planted above it is never read.
    - `verifyDepsBeforeRun=error`: pnpm 10 may install before `pnpm test`, `run` or `exec`,
      with the import method its settings name, not prepare's copies; a gate must run what
      prepare installed. `npm_config_…` beats `.npmrc`, and `pnpm_config_…` beats
      `pnpm-workspace.yaml`, including a key spelled with `${VAR:-…}`, which pnpm expands.
      `gates/command_gate.py` also refuses a gate that reaches pnpm when the file asks to
      install."""
    if program_name(program) != "pnpm":
        return {}
    return {
        "NPM_CONFIG_WORKSPACE_DIR": str(root),
        "npm_config_verify_deps_before_run": "error",
        "pnpm_config_verify_deps_before_run": "error",
    }


def pnpm_guard_env(program: str, root: Path) -> dict[str, str]:
    """What every gate and the prepare step get, whatever `program` (argv[0]) is, on top of
    `cache_env`: `pnpm_env`'s variables. A gate can reach pnpm through another launcher
    (`corepack pnpm`, `node …/pnpm.cjs`, a `package.json` script, a Makefile), and pnpm reads
    them from the environment it inherits (v0.4 decisions, session 5, item 1; checked by hand on
    pnpm 10.34.9 through corepack 0.32.0, node and an npm 11.5.2 script).

    npm warns about every `npm_config_` name it does not know ("Unknown env config", which its
    next major version stops accepting), so a program npm gets only `pnpm_config_…`, which beats
    `pnpm-workspace.yaml`; a committed `.npmrc` that asks pnpm to install beats it in an npm
    script that calls pnpm (SECURITY.md R-26). uv ignores the variables (checked by hand on uv
    0.13.6); Go and Cargo read only their own `GO…` and `CARGO_…` names."""
    env = pnpm_env("pnpm", root)
    if program_name(program) == "npm":
        return {"pnpm_config_verify_deps_before_run": env["pnpm_config_verify_deps_before_run"]}
    return env


def cache_env(program: str, cache: Path, temp: Path) -> dict[str, str]:
    """The variables that point `program` (an argv[0]) at the run's cache. Go also gets its build
    cache in the attempt's `temp` dir, which no other attempt shares."""
    name = program_name(program)
    env = {var: str(cache / sub) for var, sub in _CACHE_ENV.get(name, ())}
    if "GOMODCACHE" in env:
        env["GOCACHE"] = str(temp / "go-build")
    env.update(_COPY_ENV.get(name, {}))
    return env


def run_cache(repo: Path, run_id: str, *, home: Path) -> Path:
    """Create the cache of run `run_id` (mode 0700), outside the repository (exit 6 inside), with
    the user's Cargo settings seeded into its `CARGO_HOME` and every directory and lock file
    prepare may write already there (`PREPARE_WRITABLE`). One left behind by a run that was
    killed is removed first: a resumed run starts empty."""
    if not _RUN_ID.fullmatch(run_id):
        raise UsageError(f"not a run ID: {run_id[:40]!r}")
    real = Path(os.path.realpath(repo))
    base = cache_root() / PACKAGES_DIR / repo_id(real)
    path = outside_repo(base / run_id, real, "the run's package cache")
    remove_tree(path)
    base.mkdir(mode=0o700, parents=True, exist_ok=True)
    path.mkdir(mode=0o700)
    (path / CARGO_DIR).mkdir(mode=0o700)
    seed_cargo(path, home)
    for rel in PREPARE_WRITABLE:
        if rel.rsplit("/", 1)[-1] in CARGO_LOCK_FILES:
            os.close(os.open(path / rel, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                             0o600))  # fmt: skip
        else:
            (path / rel).mkdir(mode=0o700)
    return path


def seed_cargo(cache: Path, home: Path) -> None:
    """Copy the user's `~/.cargo/config.toml` (or `config`) into the run's `CARGO_HOME`, so their
    mirrors and source replacements still apply once `CARGO_HOME` moves. Only a regular file of
    at most `MAX_CARGO_CONFIG_BYTES` is copied; credentials never are. The user's home is theirs,
    so a link there is followed."""
    for name in ("config.toml", "config"):
        source = home / ".cargo" / name
        data = _small_regular_file(source)
        if data is None:
            continue
        target = cache / CARGO_DIR
        target.mkdir(mode=0o700, parents=True, exist_ok=True)
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW
        with os.fdopen(os.open(target / name, flags, 0o600), "wb") as handle:
            handle.write(data)
        return


def _small_regular_file(path: Path) -> bytes | None:
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NONBLOCK)
    except OSError:
        return None
    if not stat.S_ISREG(os.fstat(fd).st_mode):
        os.close(fd)
        return None
    with os.fdopen(fd, "rb") as handle:
        data = handle.read(MAX_CARGO_CONFIG_BYTES + 1)
    return None if len(data) > MAX_CARGO_CONFIG_BYTES else data


def remove_tree(path: Path) -> None:
    """Delete `path` and everything in it. Go leaves its module cache read-only, and repository
    code may have made a directory unreadable, so every directory is made accessible before it
    is entered. Each is opened relative to its parent's descriptor without following links, so
    neither a link planted in the cache nor a directory swapped for one changes anything
    outside it."""
    if not path.is_dir() or path.is_symlink():
        path.unlink(missing_ok=True)
        return
    _make_writable(None, str(path))
    for _, dirnames, _, dirfd in os.fwalk(path, follow_symlinks=False):
        for name in dirnames:
            _make_writable(dirfd, name)
    shutil.rmtree(path, ignore_errors=True)


def _make_writable(dirfd: int | None, name: str) -> None:
    """`chmod 0700` the directory `name` (relative to `dirfd`), never through a link. semgrep's
    insecure-file-permissions rule flags any mode with an execute bit; 0700 is owner-only, and a
    directory needs `x` to be entered and emptied."""
    try:  # macOS: fchmodat with AT_SYMLINK_NOFOLLOW
        # nosemgrep: insecure-file-permissions
        os.chmod(name, 0o700, dir_fd=dirfd, follow_symlinks=False)
        return
    except (NotImplementedError, ValueError, OSError):
        pass  # Linux refuses the pair: ValueError with dir_fd, NotImplementedError without
    try:
        fd = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=dirfd)
    except OSError:
        # An unreadable directory gives no descriptor: change it by name, once it is known to be
        # a directory and not a link.
        with suppress(OSError):
            if stat.S_ISDIR(os.stat(name, dir_fd=dirfd, follow_symlinks=False).st_mode):
                # nosemgrep: insecure-file-permissions
                os.chmod(name, 0o700, dir_fd=dirfd)
        return
    try:
        # nosemgrep: insecure-file-permissions
        os.fchmod(fd, 0o700)
    finally:
        os.close(fd)
