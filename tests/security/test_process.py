"""The process runner (SECURITY.md §8 and §10 rule 6, C-12).

The child processes are Python one-liners run with `sys.executable`. Tests that leave a
process behind on purpose record its PID in a file and kill it afterwards.
"""

import asyncio
import json
import math
import os
import signal
import socket
import sys
import time
from collections.abc import Callable, Iterator
from pathlib import Path

import pytest
import pytest_socket

from aipm.domain.errors import ExitCode, MissingCapability, PolicyViolation, UsageError
from aipm.execution import process
from aipm.execution.process import (
    BASE_ENV_ALLOWLIST,
    FIXED_ENV,
    ProcessResult,
    build_env,
    run_safe,
    run_safe_async,
)
from aipm.execution.sandbox import ProcessKind, SandboxProfile
from aipm.security.network import NetworkPolicy, NetworkProfile
from tests.conftest import FakeSecrets

pytestmark = pytest.mark.usefixtures("allow_unix_sockets")

PY = sys.executable
SPAWN = (
    "import subprocess, sys\n"
    "p = subprocess.Popen([sys.executable, '-c', 'import time; time.sleep(60)']{extra})\n"
    "open(sys.argv[1], 'w').write(str(p.pid))\n"
)
# macOS and Python's own locale coercion may add these to a child's environment.
PLATFORM_ENV = {"__CF_USER_TEXT_ENCODING", "LC_CTYPE"}

type Runner = Callable[..., ProcessResult]


def alive(pid: int) -> bool:
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    return True


def wait_dead(pid: int, timeout: float = 5.0) -> bool:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if not alive(pid):
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
    """PIDs a test leaves running on purpose; killed at teardown."""
    pids: list[int] = []
    yield pids
    for pid in pids:
        try:
            os.kill(pid, signal.SIGKILL)
        except ProcessLookupError:
            pass


def sync_runner(*argv: str, cwd: Path, **kwargs: object) -> ProcessResult:
    kwargs.setdefault("env", build_env())
    kwargs.setdefault("timeout_s", 30.0)
    return run_safe(list(argv), cwd=cwd, **kwargs)  # type: ignore[arg-type]


def async_runner(*argv: str, cwd: Path, **kwargs: object) -> ProcessResult:
    kwargs.setdefault("env", build_env())
    kwargs.setdefault("timeout_s", 30.0)
    return asyncio.run(run_safe_async(list(argv), cwd=cwd, **kwargs))  # type: ignore[arg-type]


BOTH = pytest.mark.parametrize("runner", [sync_runner, async_runner], ids=["sync", "async"])


def test_only_unix_sockets_are_allowed_for_asyncio() -> None:
    with pytest.raises(pytest_socket.SocketBlockedError):
        socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    socket.socket(socket.AF_UNIX, socket.SOCK_STREAM).close()


# ---------------------------------------------------------------- results


@BOTH
def test_captures_output_and_exit_code(runner: Runner, tmp_path: Path) -> None:
    code = "import sys; print('out'); print('err', file=sys.stderr); sys.exit(3)"
    result = runner(PY, "-c", code, cwd=tmp_path)
    assert result.argv == (PY, "-c", code)
    assert result.returncode == 3
    assert result.stdout == b"out\n"
    assert result.stderr == b"err\n"
    assert not result.timed_out
    assert not result.truncated
    assert result.dropped_bytes == 0
    assert result.duration_s > 0


@BOTH
def test_runs_in_the_given_directory(runner: Runner, tmp_path: Path) -> None:
    result = runner(PY, "-c", "import os; print(os.getcwd())", cwd=tmp_path)
    assert os.path.realpath(result.stdout.decode().strip()) == os.path.realpath(tmp_path)


@BOTH
def test_stdin_is_closed_unless_given(runner: Runner, tmp_path: Path) -> None:
    result = runner(PY, "-c", "import sys; print(repr(sys.stdin.read()))", cwd=tmp_path)
    assert result.stdout == b"''\n"


@BOTH
def test_stdin_is_delivered(runner: Runner, tmp_path: Path) -> None:
    code = "import sys; sys.stdout.write(sys.stdin.read().upper())"
    assert runner(PY, "-c", code, cwd=tmp_path, stdin=b"hello").stdout == b"HELLO"


@BOTH
def test_stdin_to_a_process_that_does_not_read_it(runner: Runner, tmp_path: Path) -> None:
    result = runner(PY, "-c", "pass", cwd=tmp_path, stdin=b"x" * 5_000_000)
    assert result.returncode == 0


@BOTH
def test_output_is_capped_and_the_drop_recorded(runner: Runner, tmp_path: Path) -> None:
    code = "import sys; sys.stdout.write('a' * 3_000_000); sys.stderr.write('e' * 10)"
    result = runner(PY, "-c", code, cwd=tmp_path, max_output_bytes=1000)
    assert result.stdout == b"a" * 1000
    assert result.stderr == b"e" * 10
    assert result.truncated
    assert result.dropped_bytes == 3_000_000 - 1000


# ---------------------------------------------------------------- environment


@BOTH
def test_child_sees_only_the_constructed_environment(
    runner: Runner, tmp_path: Path, fake_secrets: FakeSecrets
) -> None:
    env = build_env(extra={"AIPM_EXTRA": "1"})
    code = "import json, os; print(json.dumps(dict(os.environ)))"
    seen: dict[str, str] = json.loads(runner(PY, "-c", code, cwd=tmp_path, env=env).stdout)
    assert set(seen) - PLATFORM_ENV == set(env) - PLATFORM_ENV
    fake_secrets.assert_absent(json.dumps(seen))
    assert seen["TERM"] == "dumb"
    assert seen["NO_COLOR"] == "1"
    assert seen["CI"] == "1"


def test_build_env_copies_only_the_allowlist() -> None:
    source = {"PATH": "/bin", "HOME": "/h", "ANTHROPIC_API_KEY": "k" * 20, "TERM": "xterm"}
    env = build_env(source=source)
    assert env == {"PATH": "/bin", "HOME": "/h", **FIXED_ENV}
    assert set(BASE_ENV_ALLOWLIST) >= {"PATH", "HOME", "LANG", "TMPDIR", "USER"}


def test_build_env_extra_cannot_override_the_fixed_values() -> None:
    env = build_env((), {"TERM": "xterm-256color", "CI": "0", "FOO": "bar"}, source={})
    assert env == {"FOO": "bar", **FIXED_ENV}


@pytest.mark.parametrize(
    "extra",
    [{"A=B": "x"}, {"": "x"}, {"1A": "x"}, {"A": "x\x00y"}, {"A": 1}, {2: "x"}],
)
def test_build_env_rejects_bad_names_and_values(extra: dict[object, object]) -> None:
    with pytest.raises(UsageError):
        build_env((), extra, source={})  # type: ignore[arg-type]


def test_os_environ_is_never_passed_through(tmp_path: Path) -> None:
    with pytest.raises(PolicyViolation, match="never passed"):
        run_safe([PY, "-c", "pass"], cwd=tmp_path, env=os.environ, timeout_s=5)


# ---------------------------------------------------------------- argument checks


@pytest.mark.parametrize(
    ("kwargs", "match"),
    [
        ({"argv": "echo hi"}, "never a command string"),
        ({"argv": None}, "never a command string"),
        ({"argv": []}, "empty"),
        ({"argv": [PY, 3]}, "without NUL"),
        ({"argv": [PY, "a\x00b"]}, "without NUL"),
        ({"timeout_s": 0}, "positive"),
        ({"timeout_s": -1.0}, "positive"),
        ({"timeout_s": math.inf}, "positive"),
        ({"timeout_s": math.nan}, "positive"),
        ({"max_output_bytes": -1}, "negative"),
        ({"env": [("PATH", "/bin")]}, "mapping"),
        ({"env": {"A=B": "x"}}, "invalid environment variable name"),
    ],
)
@pytest.mark.parametrize("variant", ["sync", "async"])
def test_invalid_calls_are_refused(
    tmp_path: Path, kwargs: dict[str, object], match: str, variant: str
) -> None:
    call: dict[str, object] = {
        "argv": [PY, "-c", "pass"],
        "cwd": tmp_path,
        "env": build_env(),
        "timeout_s": 5.0,
    }
    call.update(kwargs)
    with pytest.raises(UsageError, match=match):
        if variant == "sync":
            run_safe(**call)  # type: ignore[arg-type]
        else:
            asyncio.run(run_safe_async(**call))  # type: ignore[arg-type]


def test_missing_working_directory(tmp_path: Path) -> None:
    with pytest.raises(UsageError, match="does not exist"):
        run_safe([PY, "-c", "pass"], cwd=tmp_path / "nope", env=build_env(), timeout_s=5)


@BOTH
def test_a_sandbox_profile_without_a_runtime_is_refused(runner: Runner, tmp_path: Path) -> None:
    """Prompt 06 replaced the blanket refusal: a profile still never runs unsandboxed."""
    network = NetworkPolicy(NetworkProfile.NONE)
    profile = SandboxProfile(
        ProcessKind.GATE, network, runtime=str(tmp_path / "no-srt"), settings_dir=tmp_path
    )
    with pytest.raises(MissingCapability, match="cannot be run") as info:
        runner(PY, "-c", "pass", cwd=tmp_path, sandbox=profile)
    assert info.value.exit_code is ExitCode.MISSING_TOOL


# ---------------------------------------------------------------- timeouts and process groups


@BOTH
def test_timeout_kills_the_whole_process_group(
    runner: Runner, tmp_path: Path, leftovers: list[int]
) -> None:
    pid_file = tmp_path / "grandchild.pid"
    code = SPAWN.format(extra="") + "import time; time.sleep(60)\n"
    result = runner(PY, "-c", code, str(pid_file), cwd=tmp_path, timeout_s=1.5)
    grandchild = read_pid(pid_file)
    leftovers.append(grandchild)
    assert result.timed_out
    assert result.returncode == -signal.SIGTERM
    assert result.duration_s < 10
    assert wait_dead(grandchild)


@BOTH
def test_sigkill_follows_an_ignored_sigterm(
    runner: Runner, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(process, "KILL_GRACE_S", 0.5)
    code = (
        "import signal, sys, time\n"
        "signal.signal(signal.SIGTERM, signal.SIG_IGN)\n"
        "print('ready', flush=True)\n"
        "time.sleep(60)\n"
    )
    result = runner(PY, "-c", code, cwd=tmp_path, timeout_s=1.0)
    assert result.timed_out
    assert result.returncode == -signal.SIGKILL
    assert result.stdout == b"ready\n"


@BOTH
def test_background_children_do_not_outlive_the_call(
    runner: Runner, tmp_path: Path, leftovers: list[int]
) -> None:
    pid_file = tmp_path / "grandchild.pid"
    result = runner(PY, "-c", SPAWN.format(extra=""), str(pid_file), cwd=tmp_path)
    grandchild = read_pid(pid_file)
    leftovers.append(grandchild)
    assert result.returncode == 0
    assert not result.timed_out
    assert result.duration_s < 10
    assert wait_dead(grandchild)


@BOTH
def test_an_escaped_child_holding_the_pipe_only_delays_by_the_drain_time(
    runner: Runner, tmp_path: Path, leftovers: list[int], monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(process, "DRAIN_S", 0.5)
    pid_file = tmp_path / "escaped.pid"
    code = SPAWN.format(extra=", start_new_session=True") + "print('done', flush=True)\n"
    result = runner(PY, "-c", code, str(pid_file), cwd=tmp_path)
    leftovers.append(read_pid(pid_file))
    assert result.returncode == 0
    assert result.stdout == b"done\n"
    assert result.duration_s < 10


def test_an_interrupt_kills_the_group(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, leftovers: list[int]
) -> None:
    pid_file = tmp_path / "child.pid"

    def interrupted(proc: object, timeout_s: float) -> bool:
        read_pid(pid_file)
        raise KeyboardInterrupt

    monkeypatch.setattr(process, "_wait", interrupted)
    code = "import os, sys, time; open(sys.argv[1], 'w').write(str(os.getpid())); time.sleep(60)"
    with pytest.raises(KeyboardInterrupt):
        run_safe([PY, "-c", code, str(pid_file)], cwd=tmp_path, env=build_env(), timeout_s=30)
    child = read_pid(pid_file)
    leftovers.append(child)
    assert wait_dead(child)


def test_cancelling_the_async_call_kills_the_group(tmp_path: Path, leftovers: list[int]) -> None:
    pid_file = tmp_path / "child.pid"
    code = "import os, sys, time; open(sys.argv[1], 'w').write(str(os.getpid())); time.sleep(60)"

    async def scenario() -> None:
        task = asyncio.create_task(
            run_safe_async(
                [PY, "-c", code, str(pid_file)], cwd=tmp_path, env=build_env(), timeout_s=30
            )
        )
        await asyncio.to_thread(read_pid, pid_file)
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task

    asyncio.run(scenario())
    child = read_pid(pid_file)
    leftovers.append(child)
    assert wait_dead(child)
