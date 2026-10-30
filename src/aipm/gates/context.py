"""What every gate of one `verify` attempt shares, and how owned paths become argv values.

`{paths}` expands to the task's owned paths that exist: a literal path as itself, `dir/**` as
the directory, any other glob as the files it matches (bounded). Each value passes
`safe_relpath`, so a link out of the workspace or onto a protected path is refused (exit 6).
"""

import os
import stat
from collections.abc import Callable, Sequence
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path

from aipm.config.schema import Config
from aipm.domain.models import ChangeSet, ChangeStatus, GateWorkspace, Task
from aipm.scanners.base import ScanContext
from aipm.scanners.registry import Fetch
from aipm.security.diff_checks import glob_match, is_test_path
from aipm.security.paths import SafeRelPath, safe_relpath
from aipm.security.redact import Redactor

MAX_WALK = 20_000
SKIP_DIRS = frozenset({".git", ".pm", "node_modules", ".venv", "__pycache__", ".tox"})


@dataclass(frozen=True, slots=True)
class GateContext:
    """One attempt's gates: the work tree, the task, the config and the facts around them.

    `runtime` is the `srt` path, or `None` when gates run without a sandbox. `review` asks the
    AC reviewer (an LLM role) and `fetch` the package registries; tests replace both.
    """

    ws: GateWorkspace
    task: Task
    cfg: Config
    changes: ChangeSet
    redactor: Redactor
    home: Path
    now: datetime
    runtime: str | None = None
    fetch: Fetch | None = None
    warnings: list[str] = field(default_factory=list[str])

    @property
    def root(self) -> Path:
        """The work tree the gates run in."""
        return self.ws.root

    def scan_context(self) -> ScanContext:
        """What a scanner needs from this attempt."""
        return ScanContext(
            repo=self.ws.root, temp_dir=self.ws.temp_dir, runtime=self.runtime,
            redactor=self.redactor,
        )  # fmt: skip

    def protected_extra(self) -> tuple[str, ...]:
        """`security.extra_protected_paths`."""
        return tuple(self.cfg.security.extra_protected_paths)

    def test_roots(self) -> tuple[str, ...]:
        """The stack's test roots (`tests` by default)."""
        return tuple(self.cfg.test_roots) or ("tests",)


def _wild(part: str) -> bool:
    return "*" in part or "?" in part


def _prefix(parts: Sequence[str]) -> str:
    """The components of a glob before its first wildcard."""
    out: list[str] = []
    for part in parts:
        if _wild(part):
            break
        out.append(part)
    return "/".join(out)


def _walk(root: Path, start: str, budget: list[int]) -> list[str]:
    """Files under `start` (relative), without following links, skipping tool directories."""
    found: list[str] = []
    base = root / start if start else root
    try:
        info = os.lstat(base)
    except OSError:
        return found
    if not stat.S_ISDIR(info.st_mode):
        return found
    for current, dirs, files in os.walk(base, followlinks=False):
        dirs[:] = sorted(d for d in dirs if d not in SKIP_DIRS)
        rel_dir = os.path.relpath(current, root).replace(os.sep, "/")
        for name in sorted(files):
            budget[0] -= 1
            if budget[0] < 0:
                return found
            found.append(name if rel_dir == "." else f"{rel_dir}/{name}")
    return found


def owned_files(root: Path, task: Task) -> list[str]:
    """Every existing file an owned glob matches (bounded by `MAX_WALK` entries)."""
    budget = [MAX_WALK]
    seen: set[str] = set()
    for glob in task.owns_files:
        parts = glob.split("/")
        if not any(_wild(p) for p in parts):
            path = root / glob
            if path.is_file() and not path.is_symlink():
                seen.add(glob)
            elif path.is_dir() and not path.is_symlink():
                seen.update(_walk(root, glob, budget))
            continue
        seen.update(p for p in _walk(root, _prefix(parts), budget) if glob_match(p, glob))
    return sorted(seen)


def owned_paths(
    root: Path, task: Task, *, extra_protected: Sequence[str] = ()
) -> list[SafeRelPath]:
    """The `{paths}` values: owned paths that exist, as few as possible, each `safe_relpath`."""
    values: list[str] = []
    for glob in task.owns_files:
        parts = glob.split("/")
        if not any(_wild(p) for p in parts):
            if os.path.lexists(root / glob):
                values.append(glob)
        elif parts[-1] == "**" and not any(_wild(p) for p in parts[:-1]):
            directory = "/".join(parts[:-1])
            if (root / directory).is_dir():
                values.append(directory)
        else:
            budget = [MAX_WALK]
            values += [p for p in _walk(root, _prefix(parts), budget) if glob_match(p, glob)]
    unique = sorted(set(values))
    return [safe_relpath(root, value, extra_protected=extra_protected) for value in unique]


def changed_files(changes: ChangeSet, *, keep: Callable[[str], bool] = lambda _: True) -> list[str]:
    """Changed paths that still exist, outside `.pm/`."""
    return [
        c.path
        for c in changes.files
        if c.status is not ChangeStatus.DELETED and not c.path.startswith(".pm/") and keep(c.path)
    ]


def test_files(ctx: GateContext) -> list[str]:
    """The test files `ac_trace` searches: changed ones and owned ones."""
    roots = ctx.test_roots()
    owned = [p for p in owned_files(ctx.root, ctx.task) if is_test_path(p, roots)]
    changed = changed_files(ctx.changes, keep=lambda p: is_test_path(p, roots))
    return sorted(set(owned) | set(changed))
