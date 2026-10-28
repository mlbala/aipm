"""Path validation: `safe_relpath` and `safe_rel_glob` (SECURITY.md §7.4, §10 rule 5).

The only L0 module allowed read-only filesystem calls (`lstat`, `realpath`), to detect
symlinks that escape the workspace (ARCHITECTURE §5.1).
"""

from pathlib import Path
from typing import NewType

SafeRelPath = NewType("SafeRelPath", str)
"""A relative path inside the workspace: no `..`, no leading `-`, no NUL, no escaping link."""

SafeRelGlob = NewType("SafeRelGlob", str)
"""A relative glob with the same rules, outside protected paths and `.pm/`."""


def safe_relpath(root: Path, path: str) -> SafeRelPath:
    """Validate `path` against `root`, or raise `PolicyViolation`."""
    raise NotImplementedError("v0.1: build prompt 02")


def safe_rel_glob(glob: str) -> SafeRelGlob:
    """Validate an ownership glob from a plan, or raise `PolicyViolation`."""
    raise NotImplementedError("v0.1: build prompt 02")
