"""Private JSON files in the user state directory (mode 0600, written atomically, never via links).

The trust store, attempt snapshots and the `.pm/` write ledger live outside the repository, so an
agent working in it cannot forge them. `HOME` and `XDG_STATE_HOME` decide where that is, and a
repository `.env` can set both, so a location inside the repository is refused (exit 6).
"""

import os
import secrets
import stat
from contextlib import suppress
from pathlib import Path

import platformdirs

from aipm.domain.errors import PolicyViolation
from aipm.security.paths import is_within


def state_dir(repo_root: Path | None = None) -> Path:
    """`<user_state_dir>/aipm`, refused (exit 6) when it lies inside `repo_root`."""
    path = Path(platformdirs.user_state_dir("aipm", appauthor=False))
    if repo_root is not None and is_within(path, repo_root):
        raise PolicyViolation(
            f"the aipm state directory {str(path)[:200]} is inside the repository",
            hint="Check HOME and XDG_STATE_HOME, which a repository .env loaded by a tool such "
            "as pipenv can set.",
        )
    return path


def read_private(path: Path, *, limit: int) -> bytes | None:
    """The bytes of a private file of ours; `None` when it does not exist.

    A link, a non-regular file, another owner, group or world write access, or a file over
    `limit` raises `PolicyViolation` (exit 6).
    """
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    except FileNotFoundError:
        return None
    except OSError as exc:
        raise PolicyViolation(f"cannot read {path} safely ({exc.strerror})") from None
    with os.fdopen(fd, "rb") as handle:
        info = os.fstat(handle.fileno())
        if not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid() or info.st_mode & 0o022:
            raise PolicyViolation(f"{path} is not a private file of yours")
        data = handle.read(limit + 1)
    if len(data) > limit:
        raise PolicyViolation(f"{path} is larger than {limit} bytes")
    return data


def write_private(path: Path, data: bytes) -> None:
    """Write `data` to `path` atomically with mode 0600, creating parents with mode 0700."""
    directory = path.parent
    directory.mkdir(mode=0o700, parents=True, exist_ok=True)
    if path.is_symlink():
        raise PolicyViolation(f"{path} is a symlink; refusing to write through it")
    tmp = directory / f".{path.name}.tmp-{os.getpid()}-{secrets.token_hex(4)}"
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    try:
        with os.fdopen(fd, "wb") as handle:
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
        tmp.replace(path)
    except BaseException:
        with suppress(FileNotFoundError):
            tmp.unlink()
        raise


def remove_private(path: Path) -> bool:
    """Remove a private file; returns whether there was one."""
    try:
        path.unlink()
    except FileNotFoundError:
        return False
    return True
