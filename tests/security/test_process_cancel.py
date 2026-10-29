"""Cancelling or failing an async run kills the group and leaves no zombie (Python 3.13+).

On Linux, asyncio reaps children inside the event loop (through a pidfd), so a killed leader
could stay a zombie once the loop stopped. A cancelled call now waits for the reap.
"""

import asyncio
import os
import sys
import time
from collections.abc import Iterator
from pathlib import Path

import pytest

from aipm.execution import process
from aipm.execution.process import build_env, run_safe_async

pytestmark = pytest.mark.usefixtures("allow_unix_sockets")  # the asyncio loop self-pipe
PY = sys.executable
CODE = "import os, sys, time; open(sys.argv[1], 'w').write(str(os.getpid())); time.sleep(60)"


def gone(pid: int) -> bool:
    """No such process, or only a zombie of one (Linux shows those in /proc)."""
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return True
    stat = Path(f"/proc/{pid}/stat")
    return stat.exists() and stat.read_text(encoding="utf-8").rsplit(")", 1)[1].split()[0] == "Z"


def reaped(pid: int, timeout: float = 5.0) -> bool:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            os.kill(pid, 0)
        except ProcessLookupError:
            return True
        time.sleep(0.05)
    return False


def read_pid(path: Path, timeout: float = 10.0) -> int:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        text = path.read_text(encoding="utf-8") if path.exists() else ""
        if text.strip():
            return int(text)
        time.sleep(0.02)
    raise AssertionError(f"no PID written to {path}")


@pytest.fixture
def leftovers() -> Iterator[list[int]]:
    pids: list[int] = []
    yield pids
    for pid in pids:
        try:
            os.kill(pid, 9)
        except ProcessLookupError:
            pass


@pytest.mark.parametrize("attempt", range(5))
def test_a_cancelled_call_leaves_no_zombie(
    tmp_path: Path, leftovers: list[int], attempt: int
) -> None:
    pid_file = tmp_path / f"child-{attempt}.pid"

    async def scenario() -> None:
        task = asyncio.create_task(
            run_safe_async([PY, "-c", CODE, str(pid_file)], cwd=tmp_path, env=build_env(),
                           timeout_s=30)
        )  # fmt: skip
        await asyncio.to_thread(read_pid, pid_file)
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task

    asyncio.run(scenario())
    child = read_pid(pid_file)
    leftovers.append(child)
    assert reaped(child, timeout=0.5), "the leader is reaped before the call returns"


def test_another_error_while_waiting_kills_the_group(
    tmp_path: Path, leftovers: list[int], monkeypatch: pytest.MonkeyPatch
) -> None:
    pid_file = tmp_path / "child.pid"

    async def failing(proc: object, timeout_s: float) -> bool:
        await asyncio.to_thread(read_pid, pid_file)
        raise RuntimeError("boom")

    monkeypatch.setattr(process, "_await_exit", failing)
    with pytest.raises(RuntimeError, match="boom"):
        asyncio.run(run_safe_async([PY, "-c", CODE, str(pid_file)], cwd=tmp_path,
                                   env=build_env(), timeout_s=30))  # fmt: skip
    child = read_pid(pid_file)
    leftovers.append(child)
    deadline = time.monotonic() + 5.0
    while not gone(child) and time.monotonic() < deadline:
        time.sleep(0.05)
    assert gone(child)
