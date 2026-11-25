"""Reading and writing the user config for `aipm setup` (ADR-0033).

The user config can hold user-only keys (`llm.base_url`, `llm.api_key_env`), so the one write
path aipm has for it is strict:

- the target must not lie inside any git work tree, whatever variable chose it;
- every directory on the way is opened without following symbolic links, and the target's
  directory must be owned by the user and not writable by group or others;
- missing directories are created with mode 0700, and the file is written to a temporary name
  and renamed into place with mode 0600; a symbolic link at the target is refused.
"""

import os
import stat
from pathlib import Path

from aipm.config.locations import git_root
from aipm.domain.errors import PolicyViolation, SchemaError, UsageError
from aipm.state.yamlio import MAX_YAML_BYTES

_DIR_FLAGS = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW


def _nearest_existing(path: Path) -> Path:
    for candidate in (path, *path.parents):
        if os.path.lexists(candidate):
            return candidate
    return Path(path.anchor or "/")


def check_target(path: Path) -> None:
    """Refuse a relative target, or one inside a git work tree (exit 6)."""
    if not path.is_absolute():
        raise UsageError(f"the user config path {str(path)[:200]} is not absolute")
    if git_root(_nearest_existing(path.parent)) is not None:
        raise PolicyViolation(
            f"refusing to write the user config inside a git work tree: {str(path)[:200]}",
            hint="Point AIPM_CONFIG at a file outside every repository, or write the file "
            "yourself.",
        )


def read_existing(path: Path) -> str | None:
    """The current file's text, or `None` when there is none. Refuses a link or a non-file."""
    try:
        info = path.lstat()
    except FileNotFoundError:
        return None
    if stat.S_ISLNK(info.st_mode) or not stat.S_ISREG(info.st_mode):
        raise PolicyViolation(f"the user config {str(path)[:200]} is not a regular file")
    if info.st_size > MAX_YAML_BYTES:
        raise UsageError(f"the user config {str(path)[:200]} is larger than aipm reads")
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, "rb") as handle:
        if not stat.S_ISREG(os.fstat(handle.fileno()).st_mode):
            raise PolicyViolation(f"the user config {str(path)[:200]} is not a regular file")
        try:
            return handle.read(MAX_YAML_BYTES + 1).decode("utf-8")
        except UnicodeDecodeError as exc:
            raise SchemaError(f"the user config {str(path)[:200]} is not UTF-8") from exc


def _check_ancestor(fd: int, name: str) -> None:
    """A directory on the way must be root's or the user's, and not writable by group or others
    unless it is sticky (as `/tmp` is): otherwise its owner could swap what lies below it."""
    info = os.fstat(fd)
    shared = info.st_mode & (stat.S_IWGRP | stat.S_IWOTH)
    if info.st_uid not in {0, os.getuid()} or (shared and not info.st_mode & stat.S_ISVTX):
        raise PolicyViolation(
            f"refusing to write the user config below {name!r}: another user could replace it",
            hint="Point AIPM_CONFIG at a directory only you and root can write.",
        )


def _open_parent(directory: Path) -> int:
    """Open `directory` component by component without following links, creating what is
    missing with mode 0700; the result must be owned by the user and not group/other-writable."""
    fd = os.open(directory.anchor or "/", _DIR_FLAGS)
    try:
        _check_ancestor(fd, directory.anchor or "/")
        for part in directory.parts[1:]:
            try:
                child = os.open(part, _DIR_FLAGS, dir_fd=fd)
            except FileNotFoundError:
                os.mkdir(part, 0o700, dir_fd=fd)
                child = os.open(part, _DIR_FLAGS, dir_fd=fd)
            except OSError as exc:
                raise PolicyViolation(
                    f"refusing to write the user config through {part!r}: it is a symbolic "
                    "link or not a directory",
                    hint="Write the file yourself, or point AIPM_CONFIG at a plain directory.",
                ) from exc
            os.close(fd)
            fd = child
            _check_ancestor(fd, part)
        info = os.fstat(fd)
        if info.st_uid != os.getuid() or info.st_mode & (stat.S_IWGRP | stat.S_IWOTH):
            raise PolicyViolation(
                f"refusing to write the user config into {str(directory)[:200]}: it is not "
                "yours alone (another owner, or writable by group or others)"
            )
    except BaseException:
        os.close(fd)
        raise
    return fd


def write_user_config(path: Path, text: str) -> None:
    """Write `text` to `path` atomically with mode 0600 (see the module docstring)."""
    check_target(path)
    fd = _open_parent(path.parent)
    temporary = f".{path.name}.{os.urandom(6).hex()}.tmp"
    try:
        try:
            info = os.stat(path.name, dir_fd=fd, follow_symlinks=False)
        except FileNotFoundError:
            pass
        else:
            if stat.S_ISLNK(info.st_mode) or not stat.S_ISREG(info.st_mode):
                raise PolicyViolation(f"the user config {str(path)[:200]} is not a regular file")
        out = os.open(
            temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=fd
        )
        try:
            os.write(out, text.encode("utf-8"))
            os.fsync(out)
        finally:
            os.close(out)
        os.replace(temporary, path.name, src_dir_fd=fd, dst_dir_fd=fd)
    except BaseException:
        try:
            os.unlink(temporary, dir_fd=fd)
        except FileNotFoundError:
            pass
        raise
    finally:
        os.close(fd)
