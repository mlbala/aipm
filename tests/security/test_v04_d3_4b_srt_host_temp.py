"""The v0.4 decisions, session 5, item 4 follow-up: srt's own temp dir, and the order of checks.

1. `wrap` writes srt's settings file into the profile's settings dir, which for a built-in
   scanner is its temp dir. It now checks the temp dir (`temp_env`) before writing anything, so
   a refused temp dir (exit 6) never gets a file written through it. Inside `wrap` a missing
   runtime is still reported first (exit 8). `run_safe` checks srt's private dir (below) before
   `wrap` runs, so an unusable `TMPDIR` is reported (exit 6) before a missing runtime.
2. srt keeps its host-side files (socat and mux sockets, the empty mount source, the
   credential-mask store, the bwrap arguments) in its own `TMPDIR`. That was the caller's
   `TMPDIR`: the attempt temp dir or a scanner's `<out>/tmp`, both writable from inside the
   sandbox. Each sandboxed call now gives srt a fresh private dir outside every path the profile
   may write, and removes it afterwards. The command's `TMPDIR` is unchanged: srt sets it from
   `CLAUDE_CODE_TMPDIR`.

The stub srt (`tests/fakes/bin/srt`) runs the command with srt's own environment, so a command
under it sees srt's `TMPDIR`; the real srt's behaviour is checked in
`test_real_sandbox_srt_host_temp.py`.
"""

import asyncio
import json
import sys
import tempfile
from collections.abc import Callable
from pathlib import Path

import pytest

from aipm.domain.errors import ExitCode, PolicyViolation
from aipm.execution import process
from aipm.execution.process import ProcessResult, build_env, run_safe, run_safe_async
from aipm.execution.sandbox import (
    ProcessKind,
    ProfilePaths,
    SandboxProfile,
    check_private_dir,
    profile_for,
    wrap,
)
from aipm.security.network import NetworkPolicy, NetworkProfile

STUB_SRT = Path(__file__).resolve().parents[1] / "fakes" / "bin" / "srt"
NONE = NetworkPolicy(NetworkProfile.NONE)
PY = sys.executable

pytestmark = pytest.mark.usefixtures("allow_unix_sockets")  # asyncio's self-pipe

type Runner = Callable[..., ProcessResult]


def _sync(*argv: str, **kwargs: object) -> ProcessResult:
    return run_safe(
        list(argv),
        env=kwargs.pop("env", build_env()),
        timeout_s=kwargs.pop("timeout_s", 30.0),
        **kwargs,
    )  # type: ignore[arg-type]


def _async(*argv: str, **kwargs: object) -> ProcessResult:
    env = kwargs.pop("env", build_env())
    timeout_s = kwargs.pop("timeout_s", 30.0)
    return asyncio.run(run_safe_async(list(argv), env=env, timeout_s=timeout_s, **kwargs))  # type: ignore[arg-type]


BOTH = pytest.mark.parametrize("runner", [_sync, _async], ids=["sync", "async"])

SHOW = """
import json, os, sys
tmp = os.environ.get("TMPDIR")
info = {"TMPDIR": tmp}
if tmp and os.path.isdir(tmp):
    info["mode"] = os.stat(tmp).st_mode & 0o777
with open(sys.argv[1], "w") as out:
    json.dump(info, out)
"""


def _profile(tmp_path: Path) -> tuple[SandboxProfile, Path]:
    work, temp = tmp_path / "work", tmp_path / "temp"
    work.mkdir()
    temp.mkdir(mode=0o700)
    paths = ProfilePaths(workspace=work, temp_dir=temp, home=tmp_path / "home")
    return profile_for(ProcessKind.GATE, NONE, paths, runtime=str(STUB_SRT)), work


def _show(tmp_path: Path, runner: Runner, profile: SandboxProfile, work: Path) -> dict[str, object]:
    script = tmp_path / "show.py"
    script.write_text(SHOW, encoding="utf-8")
    report = tmp_path / "report.json"
    env = build_env(extra={"TMPDIR": str(profile.temp_dir)})
    result = runner(PY, str(script), str(report), cwd=work, env=env, sandbox=profile)
    assert result.returncode == 0, result.stderr
    return json.loads(report.read_text(encoding="utf-8"))


# ------------------------------------------------------------------ 1. check before writing


def test_wrap_checks_the_temp_dir_before_writing_settings(tmp_path: Path) -> None:
    out = tmp_path / "out"
    out.mkdir()
    elsewhere = tmp_path / "elsewhere"
    elsewhere.mkdir()
    profile = SandboxProfile(
        ProcessKind.SCANNER, NONE, runtime=str(STUB_SRT), settings_dir=elsewhere,
        allow_write=(out,), temp_dir=elsewhere,
    )  # fmt: skip
    with pytest.raises(PolicyViolation, match="temp dir") as info:
        wrap(["true"], profile)
    assert info.value.exit_code is ExitCode.SECURITY_VIOLATION
    assert list(elsewhere.iterdir()) == []


def test_a_settings_dir_through_a_link_gets_nothing_written(tmp_path: Path) -> None:
    """The case the review named: a scanner's `<out>/tmp` made a link elsewhere."""
    out = tmp_path / "out"
    out.mkdir()
    target = tmp_path / "target"
    target.mkdir()
    (out / "tmp").symlink_to(target, target_is_directory=True)
    profile = SandboxProfile(
        ProcessKind.SCANNER, NONE, runtime=str(STUB_SRT), settings_dir=out / "tmp",
        allow_write=(out,), temp_dir=out / "tmp",
    )  # fmt: skip
    with pytest.raises(PolicyViolation, match="temp dir"):
        run_safe(["true"], cwd=tmp_path, env=build_env(), timeout_s=10, sandbox=profile)
    assert list(target.iterdir()) == []


# ------------------------------------------------------------------ 2. srt's own temp dir


@BOTH
def test_srt_gets_a_private_temp_dir_of_its_own(runner: Runner, tmp_path: Path) -> None:
    profile, work = _profile(tmp_path)
    info = _show(tmp_path, runner, profile, work)
    host = Path(str(info["TMPDIR"]))
    assert host != profile.temp_dir
    assert host.name.startswith("aipm-srt-")
    assert info["mode"] == 0o700
    assert not any(host.is_relative_to(entry) for entry in profile.allow_write)
    assert not host.exists(), "removed after the call"


@BOTH
def test_srt_gets_a_new_temp_dir_for_every_call(runner: Runner, tmp_path: Path) -> None:
    profile, work = _profile(tmp_path)
    first = _show(tmp_path, runner, profile, work)["TMPDIR"]
    second = _show(tmp_path, runner, profile, work)["TMPDIR"]
    assert first != second


@BOTH
def test_srt_temp_dir_is_removed_after_a_timeout(runner: Runner, tmp_path: Path) -> None:
    profile, work = _profile(tmp_path)
    marker = tmp_path / "host.txt"
    script = tmp_path / "linger.py"
    script.write_text(
        "import os, pathlib, sys, time\n"
        "pathlib.Path(sys.argv[1]).write_text(os.environ['TMPDIR'])\n"
        "time.sleep(30)\n",
        encoding="utf-8",
    )
    result = runner(PY, str(script), str(marker), cwd=work, sandbox=profile, timeout_s=2.0)
    assert result.timed_out
    assert not Path(marker.read_text(encoding="utf-8")).exists()


def test_srt_temp_dir_is_removed_when_starting_fails(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    profile, work = _profile(tmp_path)
    base = tmp_path / "base"
    base.mkdir()
    monkeypatch.setattr(tempfile, "tempdir", str(base))

    def broken(*args: object, **kwargs: object) -> object:
        raise OSError("cannot start")

    monkeypatch.setattr(process.subprocess, "Popen", broken)
    with pytest.raises(OSError, match="cannot start"):
        run_safe([PY, "-c", "pass"], cwd=work, env=build_env(), timeout_s=10, sandbox=profile)
    assert list(base.iterdir()) == []


def test_a_private_temp_dir_inside_a_writable_path_is_refused(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """aipm's own TMPDIR inside the workspace would put srt's files where the command writes."""
    profile, work = _profile(tmp_path)
    monkeypatch.setattr(tempfile, "tempdir", str(work))
    with pytest.raises(PolicyViolation, match="srt's temp dir") as info:
        run_safe([PY, "-c", "pass"], cwd=work, env=build_env(), timeout_s=10, sandbox=profile)
    assert info.value.exit_code is ExitCode.SECURITY_VIOLATION
    assert [p for p in work.iterdir() if p.name.startswith("aipm-srt-")] == []


def test_a_private_temp_dir_reached_through_a_link_into_a_writable_path_is_refused(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    profile, work = _profile(tmp_path)
    link = tmp_path / "link"
    link.symlink_to(work, target_is_directory=True)
    monkeypatch.setattr(tempfile, "tempdir", str(link))
    with pytest.raises(PolicyViolation, match="srt's temp dir"):
        run_safe([PY, "-c", "pass"], cwd=work, env=build_env(), timeout_s=10, sandbox=profile)
    assert [p for p in work.iterdir() if p.name.startswith("aipm-srt-")] == []


@BOTH
def test_an_unsandboxed_call_keeps_the_callers_tmpdir(runner: Runner, tmp_path: Path) -> None:
    env = build_env(extra={"TMPDIR": str(tmp_path)})
    code = "import os; print(os.environ['TMPDIR'])"
    result = runner(PY, "-c", code, cwd=tmp_path, env=env)
    assert result.stdout.decode().strip() == str(tmp_path)


# ------------------------------------------------------------------ 3. the settings file (review)

LIST = """
import json, os, sys
tmp = os.environ["TMPDIR"]
with open(sys.argv[1], "w") as out:
    json.dump({"TMPDIR": tmp, "files": sorted(os.listdir(tmp))}, out)
"""


@BOTH
def test_the_settings_file_is_written_in_srts_private_dir(runner: Runner, tmp_path: Path) -> None:
    """Security review (high, pre-existing): the settings file was written in the attempt temp
    dir, which a process left behind by an earlier command (R-14, macOS) could write, so it
    could rewrite the next command's policy before srt read it."""
    profile, work = _profile(tmp_path)
    script = tmp_path / "list.py"
    script.write_text(LIST, encoding="utf-8")
    report = tmp_path / "report.json"
    result = runner(PY, str(script), str(report), cwd=work, sandbox=profile)
    assert result.returncode == 0, result.stderr
    seen = json.loads(report.read_text(encoding="utf-8"))
    assert [f for f in seen["files"] if f.startswith("srt-gate-")], seen
    assert profile.temp_dir is not None
    assert list(profile.temp_dir.iterdir()) == [], "nothing written in the attempt temp dir"


def test_a_profile_without_a_temp_dir_still_hands_srt_its_settings_dir(
    tmp_path: Path,
) -> None:
    """Moving the settings file must not move the command's TMPDIR (the settings-dir fallback)."""
    profile = SandboxProfile(
        ProcessKind.GATE, NONE, runtime=str(STUB_SRT), settings_dir=tmp_path,
        allow_write=(tmp_path,),
    )  # fmt: skip
    script = tmp_path / "show_temp.py"
    code = 'import os\nprint(os.environ.get("CLAUDE_CODE_TMPDIR"))\n'
    script.write_text(code, encoding="utf-8")
    result = run_safe([PY, str(script)], cwd=tmp_path, env=build_env(), timeout_s=10,
                      sandbox=profile)  # fmt: skip
    assert result.stdout.decode().strip() == str(tmp_path)


# ------------------------------------------------------------------ 4. srt's own writable paths


def test_a_private_dir_in_srts_own_home_write_paths_is_refused(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """srt makes `~/.npm/_logs` and `~/.claude/debug` writable by itself (security review)."""
    profile, work = _profile(tmp_path)
    home = tmp_path / "home"
    logs = home / ".npm" / "_logs"
    logs.mkdir(parents=True)
    monkeypatch.setattr(Path, "home", classmethod(lambda cls: home))
    monkeypatch.setattr(tempfile, "tempdir", str(logs))
    with pytest.raises(PolicyViolation, match="srt's temp dir") as info:
        run_safe([PY, "-c", "pass"], cwd=work, env=build_env(), timeout_s=10, sandbox=profile)
    assert info.value.exit_code is ExitCode.SECURITY_VIOLATION
    assert list(logs.iterdir()) == []


@pytest.mark.parametrize(
    "host",
    ["/tmp/claude/aipm-srt-x", "/private/tmp/claude/aipm-srt-x", "/tmp/claude"],  # noqa: S108
)
def test_a_private_dir_in_srts_own_temp_dir_is_refused(tmp_path: Path, host: str) -> None:
    profile, _ = _profile(tmp_path)
    with pytest.raises(PolicyViolation, match="srt's temp dir"):
        check_private_dir(Path(host), profile)


def test_a_private_dir_in_a_writable_path_spelled_in_another_case_is_refused(
    tmp_path: Path,
) -> None:
    """macOS's disk ignores case and `realpath` keeps the case as typed (security review)."""
    profile, work = _profile(tmp_path)
    with pytest.raises(PolicyViolation, match="srt's temp dir"):
        check_private_dir(Path(str(work).swapcase()) / "aipm-srt-x", profile)


def test_a_private_dir_outside_every_writable_path_is_accepted(tmp_path: Path) -> None:
    profile, _ = _profile(tmp_path)
    check_private_dir(tmp_path / "elsewhere" / "aipm-srt-x", profile)


# ------------------------------------------------------------------ 5. removal, asyncio


def test_srt_temp_dir_is_removed_when_the_async_call_is_cancelled(tmp_path: Path) -> None:
    profile, work = _profile(tmp_path)
    marker = tmp_path / "host.txt"
    script = tmp_path / "linger.py"
    script.write_text(
        "import os, pathlib, sys, time\n"
        "pathlib.Path(sys.argv[1]).write_text(os.environ['TMPDIR'])\n"
        "time.sleep(30)\n",
        encoding="utf-8",
    )

    async def main() -> None:
        task = asyncio.create_task(
            run_safe_async(
                [PY, str(script), str(marker)],
                cwd=work,
                env=build_env(),
                timeout_s=60,
                sandbox=profile,
            )
        )
        for _ in range(500):
            if marker.exists() and marker.read_text(encoding="utf-8"):
                break
            await asyncio.sleep(0.02)
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task

    asyncio.run(main())
    assert not Path(marker.read_text(encoding="utf-8")).exists()


def test_srt_temp_dir_is_removed_when_the_async_start_fails(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    profile, work = _profile(tmp_path)
    base = tmp_path / "base"
    base.mkdir()
    monkeypatch.setattr(tempfile, "tempdir", str(base))

    async def broken(*args: object, **kwargs: object) -> object:
        raise OSError("cannot start")

    monkeypatch.setattr(process.asyncio, "create_subprocess_exec", broken)
    with pytest.raises(OSError, match="cannot start"):
        asyncio.run(run_safe_async([PY, "-c", "pass"], cwd=work, env=build_env(), timeout_s=10,
                                   sandbox=profile))  # fmt: skip
    assert list(base.iterdir()) == []
