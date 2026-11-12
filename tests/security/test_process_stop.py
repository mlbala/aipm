"""Stopping every running process group at once (ARCHITECTURE §12.6, build Ctrl-C handling).

`signal_running` reaches processes started by `run_safe` in worker threads and by
`run_safe_async` in an event loop alike; a stopped call returns its result as usual, and the
registry is empty again after every way a call can end.
"""

import asyncio
import os
import signal
import sys
import threading
import time
from collections.abc import Iterator
from pathlib import Path

import pytest

from aipm.domain.errors import UsageError
from aipm.execution import process
from aipm.execution.process import (
    ProcessResult,
    build_env,
    run_safe,
    run_safe_async,
    running_groups,
    signal_running,
)

pytestmark = pytest.mark.usefixtures("allow_unix_sockets")  # the asyncio loop self-pipe
PY = sys.executable
SLEEPER = "import os, sys, time; open(sys.argv[1], 'w').write(str(os.getpid())); time.sleep(60)"
STUBBORN = (
    "import os, signal, sys, time; signal.signal(signal.SIGTERM, signal.SIG_IGN); "
    "open(sys.argv[1], 'w').write(str(os.getpid())); time.sleep(60)"
)
FAMILY = (
    "import os, subprocess, sys, time; "
    "child = subprocess.Popen([sys.executable, '-c', 'import time; time.sleep(60)']); "
    "open(sys.argv[1], 'w').write(str(child.pid)); time.sleep(60)"
)


def wait_for(predicate: object, timeout: float = 10.0) -> None:
    assert callable(predicate)
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if predicate():
            return
        time.sleep(0.02)
    raise AssertionError("condition not met in time")


def written_pid(path: Path) -> int:
    wait_for(lambda: path.exists() and path.read_text(encoding="utf-8").strip())
    return int(path.read_text(encoding="utf-8"))


def dead(pid: int) -> bool:
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return True
    stat = Path(f"/proc/{pid}/stat")  # Linux shows an unreaped zombie as alive
    return stat.exists() and stat.read_text(encoding="utf-8").rsplit(")", 1)[1].split()[0] == "Z"


@pytest.fixture(autouse=True)
def clean_registry() -> Iterator[None]:
    assert running_groups() == ()
    yield
    signal_running(signal.SIGKILL)
    assert running_groups() == ()


async def sleeper(marker: Path, cwd: Path) -> ProcessResult:
    argv = [PY, "-c", SLEEPER, str(marker)]
    return await run_safe_async(argv, cwd=cwd, env=build_env(), timeout_s=60)


def in_thread(
    *argv: str, cwd: Path, timeout_s: float = 60.0
) -> tuple[threading.Thread, list[ProcessResult]]:
    results: list[ProcessResult] = []

    def target() -> None:
        results.append(run_safe(argv, cwd=cwd, env=build_env(), timeout_s=timeout_s))

    thread = threading.Thread(target=target, daemon=True)
    thread.start()
    return thread, results


def test_nothing_running_signals_nothing() -> None:
    assert signal_running(signal.SIGTERM) == 0


def test_sigterm_stops_a_sync_call_which_returns_its_result(tmp_path: Path) -> None:
    marker = tmp_path / "pid"
    thread, results = in_thread(PY, "-c", SLEEPER, str(marker), cwd=tmp_path)
    pid = written_pid(marker)
    assert running_groups() == (pid,)
    assert signal_running(signal.SIGTERM) == 1
    thread.join(timeout=15)
    assert not thread.is_alive()
    (result,) = results
    assert result.returncode == -signal.SIGTERM
    assert not result.timed_out
    assert running_groups() == ()


def test_sigterm_stops_an_async_call(tmp_path: Path) -> None:
    marker = tmp_path / "pid"

    async def scenario() -> ProcessResult:
        call = asyncio.create_task(sleeper(marker, tmp_path))
        pid = await asyncio.to_thread(written_pid, marker)
        assert running_groups() == (pid,)
        assert signal_running(signal.SIGTERM) == 1
        return await asyncio.wait_for(call, timeout=15)

    result = asyncio.run(scenario())
    assert result.returncode == -signal.SIGTERM
    assert running_groups() == ()


def test_sigkill_stops_a_leader_that_ignores_sigterm(tmp_path: Path) -> None:
    marker = tmp_path / "pid"
    thread, results = in_thread(PY, "-c", STUBBORN, str(marker), cwd=tmp_path)
    written_pid(marker)
    signal_running(signal.SIGTERM)
    time.sleep(0.3)
    assert thread.is_alive()  # ignored
    assert signal_running(signal.SIGKILL) == 1
    thread.join(timeout=15)
    assert results[0].returncode == -signal.SIGKILL


def test_the_whole_group_is_signalled(tmp_path: Path) -> None:
    marker = tmp_path / "child"
    thread, _ = in_thread(PY, "-c", FAMILY, str(marker), cwd=tmp_path)
    child = written_pid(marker)
    signal_running(signal.SIGTERM)
    thread.join(timeout=15)
    wait_for(lambda: dead(child))


def test_both_kinds_are_reached_by_one_call(tmp_path: Path) -> None:
    sync_marker, async_marker = tmp_path / "sync", tmp_path / "async"
    thread, results = in_thread(PY, "-c", SLEEPER, str(sync_marker), cwd=tmp_path)
    written_pid(sync_marker)

    async def scenario() -> ProcessResult:
        call = asyncio.create_task(sleeper(async_marker, tmp_path))
        await asyncio.to_thread(written_pid, async_marker)
        assert signal_running(signal.SIGTERM) == 2
        return await asyncio.wait_for(call, timeout=15)

    async_result = asyncio.run(scenario())
    thread.join(timeout=15)
    assert async_result.returncode == -signal.SIGTERM
    assert results[0].returncode == -signal.SIGTERM


@pytest.mark.parametrize("kind", ["sync", "async"])
def test_the_registry_is_empty_after_a_normal_exit_and_a_timeout(tmp_path: Path, kind: str) -> None:
    for code, timeout in (("pass", 30.0), ("import time; time.sleep(30)", 0.3)):
        argv = [PY, "-c", code]
        if kind == "sync":
            run_safe(argv, cwd=tmp_path, env=build_env(), timeout_s=timeout)
        else:
            asyncio.run(run_safe_async(argv, cwd=tmp_path, env=build_env(), timeout_s=timeout))
        assert running_groups() == ()


def test_a_refused_call_registers_nothing(tmp_path: Path) -> None:
    with pytest.raises(UsageError):
        run_safe("echo hi", cwd=tmp_path, env=build_env(), timeout_s=5)  # pyright: ignore[reportArgumentType]
    assert running_groups() == ()


def test_the_registry_is_empty_after_a_cancelled_async_call(tmp_path: Path) -> None:
    marker = tmp_path / "pid"

    async def scenario() -> None:
        call = asyncio.create_task(sleeper(marker, tmp_path))
        await asyncio.to_thread(written_pid, marker)
        call.cancel()
        with pytest.raises(asyncio.CancelledError):
            await call

    asyncio.run(scenario())
    assert running_groups() == ()


def test_the_registry_is_empty_after_an_interrupted_sync_call(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    def interrupted(proc: object, timeout_s: float) -> bool:
        raise KeyboardInterrupt

    monkeypatch.setattr(process, "_wait", interrupted)
    argv = [PY, "-c", "import time; time.sleep(30)"]
    with pytest.raises(KeyboardInterrupt):
        run_safe(argv, cwd=tmp_path, env=build_env(), timeout_s=30)
    assert running_groups() == ()
