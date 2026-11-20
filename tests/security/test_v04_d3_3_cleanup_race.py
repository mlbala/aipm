"""The v0.4 decisions, session 5, item 3: the cache cleanup's check-then-chmod race.

`remove_tree` makes each directory 0700 before emptying it. Its first try, a no-follow
`fchmodat`, works on macOS and, for a real directory, on glibc 2.32 and later (checked on glibc
2.41 with Python 3.13 and 3.14); it fails for a link, and on a libc without it. Its last
fallback, for a directory it cannot read, used to `lstat` the name and then `chmod` it by name,
following links: a process still running in the cache could swap the directory for a link in
between, and aipm changed the link's target. On Linux it now opens the directory with
`O_PATH | O_NOFOLLOW | O_DIRECTORY` and changes it through `/proc/self/fd`; elsewhere, or without
`/proc`, the directory is left behind, never changed by name.

Every test forces the first try to fail, so the fallback runs on CI's Linux too. The tests that
need `O_PATH` skip where it does not exist (macOS).
"""

import os
import stat
from collections.abc import Iterator
from pathlib import Path

import pytest

from aipm.execution import package_cache
from aipm.execution.package_cache import remove_tree

O_PATH: int = getattr(os, "O_PATH", 0)
needs_o_path = pytest.mark.skipif(not O_PATH, reason="O_PATH is Linux-only")


@pytest.fixture
def no_follow_chmod_fails(monkeypatch: pytest.MonkeyPatch) -> None:
    """A libc where the no-follow `fchmodat` fails, as CPython reports it for a link."""
    real_chmod = os.chmod

    def chmod(
        path: str | int, mode: int, *, dir_fd: int | None = None, follow_symlinks: bool = True
    ) -> None:
        if not follow_symlinks:
            raise NotImplementedError("chmod: follow_symlinks unavailable on this platform")
        real_chmod(path, mode, dir_fd=dir_fd)

    monkeypatch.setattr(os, "chmod", chmod)


def _mode(path: Path) -> int:
    return stat.S_IMODE(path.lstat().st_mode)


@pytest.fixture
def outside(tmp_path: Path) -> Path:
    """A file outside the cache that a followed link would change."""
    path = tmp_path / "outside.txt"
    path.write_text("keep", encoding="utf-8")
    path.chmod(0o600)
    return path


@pytest.fixture
def locked_cache(tmp_path: Path) -> Iterator[Path]:
    """A cache holding `locked`, a mode-0000 directory with a file in it."""
    cache = tmp_path / "cache"
    locked = cache / "locked"
    locked.mkdir(parents=True)
    (locked / "f").write_text("x", encoding="utf-8")
    locked.chmod(0o000)
    yield cache
    for left in (cache / "locked", cache / "moved"):  # let pytest clean up what a test left
        if left.is_dir() and not left.is_symlink():
            left.chmod(0o700)


def _swap(cache: Path, outside: Path) -> None:
    """What a writer still running in the cache does: move `locked` away and plant a link."""
    if not (cache / "moved").exists():
        (cache / "locked").rename(cache / "moved")
        (cache / "locked").symlink_to(outside)


@pytest.mark.usefixtures("no_follow_chmod_fails")
def test_a_directory_swapped_for_a_link_is_never_followed(
    locked_cache: Path, outside: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The swap lands after any check of `locked` (an `lstat`) and before any open of it."""
    real_stat, real_open = os.stat, os.open

    def racing_stat(
        path: str | int, *, dir_fd: int | None = None, follow_symlinks: bool = True
    ) -> os.stat_result:
        result = real_stat(path, dir_fd=dir_fd, follow_symlinks=follow_symlinks)
        if path == "locked" and dir_fd is not None:
            _swap(locked_cache, outside)
        return result

    def racing_open(path: str, flags: int, mode: int = 0o777, *, dir_fd: int | None = None) -> int:
        if path == "locked" and O_PATH and flags & O_PATH:
            _swap(locked_cache, outside)
        return real_open(path, flags, mode, dir_fd=dir_fd)

    monkeypatch.setattr(os, "stat", racing_stat)
    monkeypatch.setattr(os, "open", racing_open)
    remove_tree(locked_cache)
    monkeypatch.undo()
    assert _mode(outside) == 0o600
    assert outside.read_text(encoding="utf-8") == "keep"


@needs_o_path
@pytest.mark.usefixtures("no_follow_chmod_fails")
def test_a_swap_after_the_open_changes_the_directory_that_was_opened(
    locked_cache: Path, outside: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The descriptor names the directory itself: a swap after the open changes nothing
    outside, and the moved directory is the one made 0700, so `rmtree` can empty it."""
    real_open, real_fstat = os.open, os.fstat
    opened: list[int] = []

    def recording_open(
        path: str, flags: int, mode: int = 0o777, *, dir_fd: int | None = None
    ) -> int:
        fd = real_open(path, flags, mode, dir_fd=dir_fd)
        if path == "locked" and flags & O_PATH:
            opened.append(fd)
        return fd

    def racing_fstat(fd: int) -> os.stat_result:
        if fd in opened:
            _swap(locked_cache, outside)
        return real_fstat(fd)

    monkeypatch.setattr(os, "open", recording_open)
    monkeypatch.setattr(os, "fstat", racing_fstat)
    remove_tree(locked_cache)
    monkeypatch.undo()
    assert opened, "the O_PATH fallback did not run"
    assert _mode(outside) == 0o600
    assert not locked_cache.exists()


@needs_o_path
@pytest.mark.usefixtures("no_follow_chmod_fails")
def test_a_descriptor_that_is_not_a_directory_is_never_changed(
    locked_cache: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """`O_DIRECTORY` already refuses anything else; the `fstat` check is the second lock."""
    real_open, real_fstat = os.open, os.fstat
    opened: list[int] = []

    def recording_open(
        path: str, flags: int, mode: int = 0o777, *, dir_fd: int | None = None
    ) -> int:
        fd = real_open(path, flags, mode, dir_fd=dir_fd)
        if path == "locked" and flags & O_PATH:
            opened.append(fd)
        return fd

    def file_fstat(fd: int) -> os.stat_result:
        result = real_fstat(fd)
        if fd in opened:
            return os.stat_result((stat.S_IFREG | 0o600, *tuple(result)[1:]))
        return result

    monkeypatch.setattr(os, "open", recording_open)
    monkeypatch.setattr(os, "fstat", file_fstat)
    remove_tree(locked_cache)
    monkeypatch.undo()
    assert opened, "the O_PATH fallback did not run"
    assert _mode(locked_cache / "locked") == 0o000


@needs_o_path
@pytest.mark.usefixtures("no_follow_chmod_fails")
def test_an_unreadable_tree_is_removed_through_o_path(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    cache = tmp_path / "cache"
    inner = cache / "go-mod" / "a" / "b"
    inner.mkdir(parents=True)
    (inner / "f").write_text("x", encoding="utf-8")
    (inner.parent / "g").write_text("y", encoding="utf-8")
    for directory in (inner, inner.parent):
        directory.chmod(0o000)
    real_open = os.open
    flags_seen: list[int] = []

    def recording_open(
        path: str, flags: int, mode: int = 0o777, *, dir_fd: int | None = None
    ) -> int:
        flags_seen.append(flags)
        return real_open(path, flags, mode, dir_fd=dir_fd)

    monkeypatch.setattr(os, "open", recording_open)
    remove_tree(cache)
    monkeypatch.undo()
    assert not cache.exists()
    assert any(flags & O_PATH for flags in flags_seen), "the O_PATH fallback did not run"


def test_an_unreadable_tree_is_removed_without_forcing(tmp_path: Path) -> None:
    """macOS through the no-follow `fchmodat`, Linux through `O_PATH`."""
    cache = tmp_path / "cache"
    inner = cache / "a" / "b"
    inner.mkdir(parents=True)
    (inner / "f").write_text("x", encoding="utf-8")
    for directory in (inner, inner.parent):
        directory.chmod(0o000)
    remove_tree(cache)
    assert not cache.exists()


@pytest.mark.parametrize("missing", ["O_PATH", "/proc"])
@pytest.mark.usefixtures("no_follow_chmod_fails")
def test_without_o_path_or_proc_the_directory_is_left_and_never_changed_by_name(
    missing: str,
    locked_cache: Path,
    outside: Path,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Leaving a directory under aipm's cache root is safe; following a link is not."""
    (locked_cache / "link").symlink_to(outside)
    if missing == "O_PATH":
        monkeypatch.delattr(os, "O_PATH", raising=False)
    else:
        monkeypatch.setattr(package_cache, "_PROC_FD", str(tmp_path / "no-proc"), raising=False)
    remove_tree(locked_cache)  # no exception escapes
    monkeypatch.undo()
    assert (locked_cache / "locked").is_dir()
    assert _mode(locked_cache / "locked") == 0o000
    assert _mode(outside) == 0o600


def test_a_hard_link_in_place_of_a_directory_is_never_changed(
    tmp_path: Path, outside: Path
) -> None:
    """A writer swaps the directory for a hard link to an outside file after the walk listed
    it. A no-follow `fchmodat` would change that file (it is not a link), so the directory is
    first opened `O_DIRECTORY`, which refuses it."""
    cache = tmp_path / "cache"
    cache.mkdir()
    os.link(outside, cache / "locked")
    dirfd = os.open(cache, os.O_RDONLY | os.O_DIRECTORY)
    try:
        package_cache._make_writable(dirfd, "locked")  # pyright: ignore[reportPrivateUsage]
    finally:
        os.close(dirfd)
    assert _mode(outside) == 0o600


def test_a_directory_whose_mode_cannot_change_never_stops_the_cleanup(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """On macOS `chflags uchg` makes `fchmod` fail with EPERM; the cleanup goes on."""
    cache = tmp_path / "cache"
    (cache / "a").mkdir(parents=True)

    def refuse(fd: int, mode: int) -> None:
        raise PermissionError(1, "Operation not permitted")

    monkeypatch.setattr(os, "fchmod", refuse)
    remove_tree(cache)
    monkeypatch.undo()
    assert not cache.exists()
