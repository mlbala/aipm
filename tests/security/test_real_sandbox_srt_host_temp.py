"""The v0.4 decisions, session 5, item 4 follow-up, with the real srt: srt keeps its host-side
files in a private temp dir the sandboxed command cannot write, and the command's own `TMPDIR`
is still the profile's temp dir. srt's settings file is in that private dir, so no sandboxed
process (one left behind by an earlier command included, R-14) can rewrite it.

Needs srt on PATH (`.github/sandbox/node_modules/.bin` locally and in CI's sandbox job, where
`AIPM_REQUIRE_REAL_SRT=1` turns a missing tool into a failure). No network: the profiles are
`none`. On Linux srt binds its socat bridge sockets in that dir, so the gate test also shows
they still reach the sandbox.
"""

import json
import os
import shutil
import sys
import tempfile
from collections.abc import Iterator
from pathlib import Path

import pytest

from aipm.execution.process import build_env, run_safe
from aipm.execution.sandbox import ProcessKind, ProfilePaths, launcher_for, profile_for
from aipm.scanners.base import ScanContext, Tool, run_tool
from aipm.security.network import NetworkPolicy, NetworkProfile
from tests.security.test_real_sandbox import (
    cache,  # noqa: F401 - the fixture
    failure,
    need,
)

PROBE = """
import glob, json, os, sys
base, report = sys.argv[1], sys.argv[2]
found = sorted(glob.glob(os.path.join(base, "aipm-srt-*")))
done = {"TMPDIR": os.environ.get("TMPDIR"), "host": found, "writes": {}}
done["settings"] = {}
for host in found:
    target = os.path.join(host, "planted")
    try:
        with open(target, "w") as out:
            out.write("planted")
        done["writes"][host] = True
    except OSError:
        done["writes"][host] = False
    for name in sorted(os.listdir(host)):
        if name.startswith("srt-") and name.endswith(".json"):
            try:
                with open(os.path.join(host, name), "a") as out:
                    out.write(" ")
                done["settings"][name] = True
            except OSError:
                done["settings"][name] = False
with open(report, "w") as out:
    json.dump(done, out)
"""


@pytest.fixture
def base(monkeypatch: pytest.MonkeyPatch) -> Iterator[Path]:
    """Where aipm makes srt's private dir: a short dir of its own, so the probe finds it."""
    made = Path(tempfile.mkdtemp(prefix="aipm-t-"))
    monkeypatch.setattr(tempfile, "tempdir", str(made))
    yield made
    shutil.rmtree(made, ignore_errors=True)


def _check(done: dict[str, object], temp: Path, base: Path) -> None:
    assert Path(os.path.realpath(str(done["TMPDIR"]))) == Path(os.path.realpath(temp))
    hosts = done["host"]
    assert isinstance(hosts, list) and len(hosts) == 1, hosts  # pyright: ignore[reportUnknownArgumentType]
    assert done["writes"] == {hosts[0]: False}
    settings = done["settings"]
    assert isinstance(settings, dict) and len(settings) == 1, settings  # pyright: ignore[reportUnknownArgumentType]
    assert list(settings.values()) == [False], "srt's settings file is not writable from inside"  # pyright: ignore[reportUnknownMemberType, reportUnknownArgumentType]
    assert list(base.glob("aipm-srt-*")) == [], "removed after the call"


def test_a_gate_cannot_write_srts_own_temp_dir(tmp_path: Path, base: Path) -> None:
    srt = need("srt")
    work = base / "ws"
    temp = base / "ws-temp"
    work.mkdir()
    temp.mkdir(mode=0o700)
    script = tmp_path / "probe.py"
    script.write_text(PROBE, encoding="utf-8")
    report = work / "report.json"
    paths = ProfilePaths(workspace=work, temp_dir=temp, home=Path.home())
    profile = profile_for(
        ProcessKind.GATE, NetworkPolicy(NetworkProfile.NONE), paths,
        runtime=launcher_for(srt, work),
    )  # fmt: skip
    result = run_safe(
        [sys.executable, str(script), str(base), str(report)], cwd=work,
        env=build_env(extra={"TMPDIR": str(temp)}), timeout_s=120, sandbox=profile,
    )  # fmt: skip
    assert result.returncode == 0, failure(result)
    _check(json.loads(report.read_text(encoding="utf-8")), temp, base)


def test_a_scanner_cannot_write_srts_own_temp_dir(tmp_path: Path, base: Path) -> None:
    srt = need("srt")
    repo = base / "repo"
    repo.mkdir()
    out = base / "out"
    out.mkdir(mode=0o700)
    script = tmp_path / "probe.py"
    script.write_text(PROBE, encoding="utf-8")
    report = out / "report.json"
    ctx = ScanContext(repo=repo, temp_dir=base, runtime=launcher_for(srt, repo))
    result = run_tool(
        Tool("scanner", "install it"), sys.executable, [str(script), str(base), str(report)],
        ctx, cwd=repo, out_dir=out,
    )  # fmt: skip
    assert result.returncode == 0, failure(result)
    _check(json.loads(report.read_text(encoding="utf-8")), out / "tmp", base)
