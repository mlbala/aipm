"""The few repository files aipm writes outside `.pm/` (SECURITY.md §14.1, I-2): the context files
that hold a managed block, and a prompt saved with `aipm prompt --out`.

A cloned repository controls these paths, so nothing here follows a symbolic link: an
`AGENTS.md` that links to `~/.bashrc`, or a directory on the way that links elsewhere, is refused
(exit 6), never read or written through. Only regular files are read, with a size cap. A write
is atomic (temp file in the same directory, fsync, `os.replace`, directory fsync), keeps the
file's permission bits, and is refused if the file changed since the caller read it.
"""

import os
import secrets
import stat
from contextlib import suppress
from pathlib import Path

from aipm.domain.errors import PolicyViolation, UsageError

MAX_REPO_FILE_BYTES = 1_048_576
_TMP_MARK = ".aipm-tmp-"


def _parent(root: Path, relpath: str) -> Path:
    """The real parent directory of `relpath` under `root`; no component may be a link."""
    parts = relpath.split("/")
    if not relpath or any(p in ("", ".", "..") for p in parts):
        raise UsageError(f"not a plain relative path: {relpath!r}")
    current = root
    for part in parts[:-1]:
        current = current / part
        try:
            info = os.lstat(current)
        except FileNotFoundError:
            raise UsageError(f"the directory of {relpath} does not exist") from None
        if stat.S_ISLNK(info.st_mode) or not stat.S_ISDIR(info.st_mode):
            raise PolicyViolation(f"{relpath}: {part} is a link or not a directory")
    return current


def read_repo_bytes(root: Path, relpath: str, *, limit: int = MAX_REPO_FILE_BYTES) -> bytes | None:
    """The bytes of `root/relpath`, or None if it does not exist. Never follows a link."""
    target = _parent(root, relpath) / relpath.rsplit("/", 1)[-1]
    try:
        fd = os.open(target, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    except FileNotFoundError:
        return None
    except OSError as exc:
        raise PolicyViolation(f"{relpath} cannot be read safely ({exc.strerror})") from None
    if not stat.S_ISREG(os.fstat(fd).st_mode):
        os.close(fd)
        raise PolicyViolation(f"{relpath} is not a regular file")
    with os.fdopen(fd, "rb") as handle:
        data = handle.read(limit + 1)
    if len(data) > limit:
        raise UsageError(f"{relpath} is larger than {limit} bytes")
    return data


def write_repo_bytes(root: Path, relpath: str, data: bytes, *, expected: bytes | None) -> None:
    """Replace `root/relpath` with `data`, atomically, if it still holds `expected`.

    `expected` is the content the caller read (None: the file did not exist). If the file
    changed in between, nothing is written (exit 2).
    """
    parent = _parent(root, relpath)
    name = relpath.rsplit("/", 1)[-1]
    target = parent / name
    if read_repo_bytes(root, relpath) != expected:
        raise UsageError(
            f"{relpath} changed while aipm was preparing it; nothing was written",
            hint="Run the command again.",
        )
    mode = None if expected is None else stat.S_IMODE(os.lstat(target).st_mode)
    tmp = parent / f".{name}{_TMP_MARK}{os.getpid()}-{secrets.token_hex(4)}"
    # A new file gets 0666 minus the umask, like any editor would create it.
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o666)
    try:
        with os.fdopen(fd, "wb") as handle:
            if mode is not None:
                os.fchmod(handle.fileno(), mode)
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
        tmp.replace(target)
    except BaseException:
        with suppress(FileNotFoundError):
            tmp.unlink()
        raise
    dir_fd = os.open(parent, os.O_RDONLY)
    try:
        os.fsync(dir_fd)
    finally:
        os.close(dir_fd)
