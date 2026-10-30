"""What an attempt changed, as facts the post-change checks inspect (ARCHITECTURE §12.4 step 3).

`aipm.execution.git` builds a `ChangeSet` from the repository; `aipm.security.diff_checks`
judges it without any I/O. Paths are relative, `/`-separated and exactly as git reports them, so
a strange name is judged as itself. Contents are kept only for the files the checks read (tests,
test configuration and manifests), capped, and decoded with replacement; all of it is T2.
"""

from dataclasses import dataclass
from enum import StrEnum
from pathlib import Path


class ChangeStatus(StrEnum):
    """How a path differs from the attempt's starting point."""

    ADDED = "added"
    MODIFIED = "modified"
    DELETED = "deleted"
    TYPE_CHANGED = "type_changed"


SYMLINK_MODE = "120000"
GITLINK_MODE = "160000"


@dataclass(frozen=True, slots=True)
class FileChange:
    """One changed path.

    `mode` is the git mode now (`None` once deleted); `link_target` is the text of a symbolic
    link; `link_escapes` says it resolves outside the workspace, and `link_protected` that it
    resolves to a protected path. `before` and `after` are the contents when the checks need
    them; `truncated` says one of them was cut at the cap.
    """

    path: str
    status: ChangeStatus
    mode: str | None = None
    base_mode: str | None = None
    link_target: str | None = None
    link_escapes: bool = False
    link_protected: bool = False
    before: str | None = None
    after: str | None = None
    truncated: bool = False

    @property
    def is_symlink(self) -> bool:
        """Whether the path is a symbolic link now."""
        return self.mode == SYMLINK_MODE


@dataclass(frozen=True, slots=True)
class ChangeSet:
    """Every change an attempt made, and the integrity facts around it.

    `integrity` names each watched file outside the work tree that changed (`.git/config`,
    hooks, the agents' global config); `hidden` names ignored files on a protected path or a
    test path that changed. `.pm/` files aipm wrote itself are left out. `complete` is false
    when there were more changes than aipm reads, or a name it cannot read, or the integrity
    check failed before git ran; the checks treat that as severe.
    """

    base_sha: str
    files: tuple[FileChange, ...] = ()
    integrity: tuple[str, ...] = ()
    hidden: tuple[str, ...] = ()
    complete: bool = True

    def paths(self) -> list[str]:
        """The changed paths, in order."""
        return [change.path for change in self.files]


@dataclass(frozen=True, slots=True)
class GateWorkspace:
    """Where gates run: the work tree, the attempt's private temp dir and the base commit.

    `temp_dir` is mode 0700, outside the work tree; `{report_file}` and sandbox settings live
    there, and it is removed when the attempt ends.
    """

    root: Path
    temp_dir: Path
    base_sha: str
    run_dir: Path | None = None
