"""Finding the repository a command works on (`-C PATH`, or the current directory)."""

import os
from pathlib import Path

from aipm.domain.errors import UsageError
from aipm.state.layout import pm_root


def find_repo_root(project: Path | None) -> Path:
    """The nearest directory, from `project` (default: the current one) upwards, with `.git`.

    Only the file system is inspected; no git command runs. Raises `UsageError` (exit 2).
    """
    start = Path(os.path.realpath(project if project is not None else Path.cwd()))
    if not start.is_dir():
        raise UsageError(f"{start} is not a directory")
    for candidate in (start, *start.parents):
        if os.path.lexists(candidate / ".git"):
            return candidate
    raise UsageError(
        f"{start} is not inside a git repository",
        hint="Run `git init` first, or point aipm at a repository with -C PATH.",
    )


def require_initialized(root: Path) -> None:
    """Raise `UsageError` (exit 2) unless `aipm init` has created `.pm/`."""
    if not pm_root(root).is_dir():
        raise UsageError(f"{root} has no .pm/ directory", hint="Run `aipm init` first.")
