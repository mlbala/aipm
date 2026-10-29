"""The only module that may start a process (C-12, SECURITY.md §10 rule 6).

argv lists only, a timeout, a constructed environment (never a copy of `os.environ`), a new
process group, stdin closed unless given, and an output cap. On timeout the whole process group
gets SIGTERM, then SIGKILL after `KILL_GRACE_S`. When the leader exits, anything it left behind
in its group is killed too. A child that starts its own session escapes the group kill; it can
delay the call by at most `DRAIN_S` and keeps running until the sandbox (build prompt 06)
contains it.

Each of stdout and stderr is capped at `max_output_bytes`; the excess is read and dropped, and
the drop is recorded. Sandboxing arrives with build prompt 06: until then any profile is refused
(exit 8) rather than ignored.
"""

import asyncio
import contextlib
import math
import os
import re
import signal
import subprocess  # noqa: TID251 - the one process module (ARCHITECTURE §5.1)
import threading
import time
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import IO, cast

from aipm.domain.errors import MissingCapability, PolicyViolation, UsageError
from aipm.execution.sandbox import SandboxProfile

BASE_ENV_ALLOWLIST: tuple[str, ...] = (
    "PATH", "HOME", "LANG", "LC_ALL", "LC_CTYPE", "TMPDIR", "USER",
)  # fmt: skip
"""SECURITY.md §8: the names copied from the parent environment for every process."""
PROXY_ENV: tuple[str, ...] = ("HTTP_PROXY", "HTTPS_PROXY", "NO_PROXY", "SSL_CERT_FILE")
"""Added for the prepare step and agents only, when set (SECURITY.md §8)."""
FIXED_ENV: Mapping[str, str] = {"TERM": "dumb", "NO_COLOR": "1", "CI": "1"}

KILL_GRACE_S = 10.0
DRAIN_S = 5.0
_POLL_S = 0.01
_CHUNK = 65_536
_ENV_NAME = re.compile(r"[A-Za-z_][A-Za-z0-9_]*")


@dataclass(frozen=True, slots=True)
class ProcessResult:
    """The outcome of one process run."""

    argv: tuple[str, ...]
    returncode: int | None
    stdout: bytes
    stderr: bytes
    timed_out: bool
    truncated: bool
    duration_s: float
    dropped_bytes: int = 0


def build_env(
    base_allowlist: Iterable[str] = BASE_ENV_ALLOWLIST,
    extra: Mapping[str, str] | None = None,
    *,
    source: Mapping[str, str] | None = None,
) -> dict[str, str]:
    """Construct a process environment.

    The allowlisted names are copied from `source` (default: `os.environ`) when set, then
    `extra` is added, then `TERM=dumb`, `NO_COLOR=1` and `CI=1`, which nothing overrides.
    """
    parent = os.environ if source is None else source
    env = {name: parent[name] for name in base_allowlist if name in parent}
    env.update(extra or {})
    env.update(FIXED_ENV)
    return _check_env(env)


def _check_env(env: object) -> dict[str, str]:
    if env is os.environ:
        raise PolicyViolation("os.environ is never passed to a process; use build_env()")
    if not isinstance(env, Mapping):
        raise UsageError("env must be a mapping")
    items: Mapping[object, object] = env  # pyright: ignore[reportUnknownVariableType]
    checked: dict[str, str] = {}
    for name, value in items.items():
        if not isinstance(name, str) or not _ENV_NAME.fullmatch(name):
            raise UsageError(f"invalid environment variable name {name!r}")
        if not isinstance(value, str) or "\x00" in value:
            raise UsageError(f"environment variable {name} must be a string without NUL")
        checked[name] = value
    return checked


def _check_call(
    argv: object,
    *,
    cwd: Path,
    env: object,
    timeout_s: float,
    max_output_bytes: int,
    sandbox: SandboxProfile | None,
) -> tuple[tuple[str, ...], dict[str, str]]:
    if sandbox is not None:
        raise MissingCapability(
            "sandboxed execution is not available yet (build prompt 06)",
            hint="Run without a sandbox profile, or wait for aipm v0.2.",
        )
    if isinstance(argv, str) or not isinstance(argv, Sequence):
        raise UsageError("argv must be a list of strings, never a command string")
    items: Sequence[object] = argv  # pyright: ignore[reportUnknownVariableType]
    if not items:
        raise UsageError("argv is empty")
    if not all(isinstance(arg, str) and "\x00" not in arg for arg in items):
        raise UsageError("argv elements must be strings without NUL")
    if not (timeout_s > 0 and math.isfinite(timeout_s)):
        raise UsageError("timeout_s must be a positive number of seconds")
    if max_output_bytes < 0:
        raise UsageError("max_output_bytes must not be negative")
    if not cwd.is_dir():
        raise UsageError(f"working directory {cwd} does not exist")
    return tuple(str(arg) for arg in items), _check_env(env)


class _Capture:
    """Keeps the first `limit` bytes of a stream and counts the rest."""

    def __init__(self, limit: int) -> None:
        self._limit = limit
        self._data = bytearray()
        self._dropped = 0
        self._lock = threading.Lock()

    def add(self, chunk: bytes) -> None:
        with self._lock:
            keep = chunk[: max(self._limit - len(self._data), 0)]
            self._data += keep
            self._dropped += len(chunk) - len(keep)

    def snapshot(self) -> tuple[bytes, int]:
        with self._lock:
            return bytes(self._data), self._dropped


def _signal_group(pid: int, sig: signal.Signals) -> None:
    with contextlib.suppress(ProcessLookupError, PermissionError):
        os.killpg(pid, sig)


def _result(
    argv: tuple[str, ...],
    returncode: int | None,
    captures: tuple[_Capture, _Capture],
    *,
    timed_out: bool,
    start: float,
) -> ProcessResult:
    (stdout, out_dropped), (stderr, err_dropped) = (c.snapshot() for c in captures)
    dropped = out_dropped + err_dropped
    return ProcessResult(
        argv=argv,
        returncode=returncode,
        stdout=stdout,
        stderr=stderr,
        timed_out=timed_out,
        truncated=dropped > 0,
        duration_s=time.monotonic() - start,
        dropped_bytes=dropped,
    )


# ---------------------------------------------------------------- synchronous


def _pump(stream: IO[bytes], capture: _Capture) -> None:
    with contextlib.suppress(OSError, ValueError):
        while chunk := os.read(stream.fileno(), _CHUNK):
            capture.add(chunk)


def _feed(stream: IO[bytes], data: bytes) -> None:
    with contextlib.suppress(OSError, ValueError):
        stream.write(data)
    with contextlib.suppress(OSError, ValueError):
        stream.close()


def _wait(proc: "subprocess.Popen[bytes]", timeout_s: float) -> bool:
    """Wait for the leader; on timeout stop its group. Returns whether it timed out."""
    try:
        proc.wait(timeout=timeout_s)
    except subprocess.TimeoutExpired:
        _signal_group(proc.pid, signal.SIGTERM)
        try:
            proc.wait(timeout=KILL_GRACE_S)
        except subprocess.TimeoutExpired:
            _signal_group(proc.pid, signal.SIGKILL)
            proc.wait()
        return True
    return False


def run_safe(
    argv: Sequence[str],
    *,
    cwd: Path,
    env: Mapping[str, str],
    timeout_s: float,
    stdin: bytes | None = None,
    max_output_bytes: int = 2_000_000,
    sandbox: SandboxProfile | None = None,
) -> ProcessResult:
    """Run one process safely and return its result."""
    checked, environment = _check_call(
        argv,
        cwd=cwd,
        env=env,
        timeout_s=timeout_s,
        max_output_bytes=max_output_bytes,
        sandbox=sandbox,
    )
    captures = (_Capture(max_output_bytes), _Capture(max_output_bytes))
    start = time.monotonic()
    proc = subprocess.Popen(  # noqa: S603 - argv list, no shell, constructed env
        checked,
        cwd=cwd,
        env=environment,
        stdin=subprocess.DEVNULL if stdin is None else subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        start_new_session=True,
        close_fds=True,
        shell=False,
    )
    # Popen with PIPE always creates these streams.
    out, err = cast("IO[bytes]", proc.stdout), cast("IO[bytes]", proc.stderr)
    threads = [
        threading.Thread(target=_pump, args=(out, captures[0]), daemon=True),
        threading.Thread(target=_pump, args=(err, captures[1]), daemon=True),
    ]
    if stdin is not None:
        feed = (cast("IO[bytes]", proc.stdin), stdin)
        threads.append(threading.Thread(target=_feed, args=feed, daemon=True))
    for thread in threads:
        thread.start()
    try:
        timed_out = _wait(proc, timeout_s)
    except BaseException:  # Ctrl-C included: never leave the group running
        _signal_group(proc.pid, signal.SIGKILL)
        proc.wait()
        raise
    _signal_group(proc.pid, signal.SIGKILL)  # anything the leader left behind
    drain_until = time.monotonic() + DRAIN_S
    for thread in threads:
        thread.join(timeout=max(drain_until - time.monotonic(), 0))
    return _result(checked, proc.returncode, captures, timed_out=timed_out, start=start)


# ---------------------------------------------------------------- asyncio


async def _apump(stream: asyncio.StreamReader, capture: _Capture) -> None:
    while chunk := await stream.read(_CHUNK):
        capture.add(chunk)


async def _afeed(stream: asyncio.StreamWriter, data: bytes) -> None:
    with contextlib.suppress(OSError):
        stream.write(data)
        await stream.drain()
    with contextlib.suppress(OSError):
        stream.close()


async def _leader_exited(proc: asyncio.subprocess.Process, timeout_s: float) -> bool:  # noqa: TID251
    """Wait until the leader has exited, up to `timeout_s`.

    `Process.wait()` is not used: on Python 3.12 it returns only once every pipe is closed, so
    a background child holding stdout would keep it waiting. `returncode` is set by the child
    watcher as soon as the leader exits.
    """
    loop = asyncio.get_running_loop()
    deadline = loop.time() + timeout_s
    while proc.returncode is None:
        if loop.time() >= deadline:
            return False
        await asyncio.sleep(_POLL_S)
    return True


def _close_pipes(proc: asyncio.subprocess.Process) -> None:  # noqa: TID251
    """Close our ends of the pipes; asyncio offers no public way from a `Process`."""
    transport: asyncio.SubprocessTransport = vars(proc)["_transport"]
    transport.close()


def _stop_reading(proc: asyncio.subprocess.Process, tasks: list[asyncio.Task[None]]) -> None:  # noqa: TID251
    for task in tasks:
        task.cancel()
    _close_pipes(proc)


async def _await_exit(proc: asyncio.subprocess.Process, timeout_s: float) -> bool:  # noqa: TID251
    """The asyncio variant of `_wait`."""
    if await _leader_exited(proc, timeout_s):
        return False
    _signal_group(proc.pid, signal.SIGTERM)
    if not await _leader_exited(proc, KILL_GRACE_S):
        _signal_group(proc.pid, signal.SIGKILL)
        await _leader_exited(proc, math.inf)
    return True


async def run_safe_async(
    argv: Sequence[str],
    *,
    cwd: Path,
    env: Mapping[str, str],
    timeout_s: float,
    stdin: bytes | None = None,
    max_output_bytes: int = 2_000_000,
    sandbox: SandboxProfile | None = None,
) -> ProcessResult:
    """The asyncio variant of `run_safe`. Cancelling it kills the process group."""
    checked, environment = _check_call(
        argv,
        cwd=cwd,
        env=env,
        timeout_s=timeout_s,
        max_output_bytes=max_output_bytes,
        sandbox=sandbox,
    )
    captures = (_Capture(max_output_bytes), _Capture(max_output_bytes))
    start = time.monotonic()
    proc = await asyncio.create_subprocess_exec(  # noqa: TID251 - argv list, constructed env
        *checked,
        cwd=cwd,
        env=environment,
        stdin=subprocess.DEVNULL if stdin is None else subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        start_new_session=True,
        close_fds=True,
    )
    out = cast("asyncio.StreamReader", proc.stdout)
    err = cast("asyncio.StreamReader", proc.stderr)
    tasks = [
        asyncio.create_task(_apump(out, captures[0])),
        asyncio.create_task(_apump(err, captures[1])),
    ]
    if stdin is not None:
        tasks.append(asyncio.create_task(_afeed(cast("asyncio.StreamWriter", proc.stdin), stdin)))
    try:
        timed_out = await _await_exit(proc, timeout_s)
    except asyncio.CancelledError:
        _signal_group(proc.pid, signal.SIGKILL)
        # On Linux asyncio reaps children inside the loop (through a pidfd): wait for the killed
        # leader to be reaped, so no zombie outlives a cancelled call. SIGKILL makes this short.
        with contextlib.suppress(asyncio.CancelledError):
            await _leader_exited(proc, KILL_GRACE_S)
        _stop_reading(proc, tasks)
        raise
    except BaseException:
        _signal_group(proc.pid, signal.SIGKILL)
        _stop_reading(proc, tasks)
        raise
    _signal_group(proc.pid, signal.SIGKILL)
    _, pending = await asyncio.wait(tasks, timeout=DRAIN_S)
    if pending:
        # A process that left its session still holds the pipes: stop reading and close our
        # ends. The leader has exited, so closing the transport signals nothing.
        for task in pending:
            task.cancel()
        _close_pipes(proc)
    return _result(checked, proc.returncode, captures, timed_out=timed_out, start=start)
