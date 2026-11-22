"""The v0.4 decisions, session 5, item 4, with the real srt: a built-in scanner's `TMPDIR` is
`<out>/tmp`, it can write there and beside its report, and nowhere outside `<out>`.

Checked by hand on srt 0.0.81 (the progress doc, session 5, item 4). Runs through
`scanners.base.run_tool`, as a built-in scanner does. Needs srt on PATH
(`.github/sandbox/node_modules/.bin` locally and in CI's sandbox job, where
`AIPM_REQUIRE_REAL_SRT=1` turns a missing tool into a failure). No network: the profile is
`none`.
"""

import json
import os
import shutil
import sys
import tempfile
from collections.abc import Iterator
from pathlib import Path

import pytest

from aipm.execution.sandbox import launcher_for
from aipm.scanners.base import ScanContext, Tool, run_tool
from tests.security.test_real_sandbox import (
    cache,  # noqa: F401 - the fixture
    failure,
    need,
)

SCRIPT = """
import json, os, sys, tempfile
done = {"TMPDIR": os.environ.get("TMPDIR")}
with tempfile.NamedTemporaryFile(delete=False) as handle:
    handle.write(b"temp")
done["made"] = handle.name
for target in sys.argv[2:]:
    try:
        with open(target, "w") as out:
            out.write("planted")
        done[target] = True
    except OSError:
        done[target] = False
with open(sys.argv[1], "w") as out:
    json.dump(done, out)
"""


@pytest.fixture
def short_tmp() -> Iterator[Path]:
    """A short base dir, as `aipm scan` makes with `mkdtemp`. On Linux srt puts its socat bridge
    sockets in its own `TMPDIR`, which `run_tool` sets to `<out>/tmp`; under pytest's `tmp_path`
    the socket path passes the 107-byte limit and srt fails ("Failed to create bridge sockets")."""
    base = Path(tempfile.mkdtemp(prefix="aipm-"))
    yield base
    shutil.rmtree(base, ignore_errors=True)


def test_a_scanner_writes_its_temp_files_in_its_own_tmp(short_tmp: Path) -> None:
    srt = need("srt")
    tmp_path = short_tmp
    repo = tmp_path / "repo"
    repo.mkdir()
    out = tmp_path / "scan-out"
    out.mkdir(mode=0o700)
    script = tmp_path / "scanner.py"
    script.write_text(SCRIPT, encoding="utf-8")
    report = out / "report.json"
    outside = tmp_path / "outside"
    beside = out / "beside.txt"
    ctx = ScanContext(repo=repo, temp_dir=tmp_path, runtime=launcher_for(srt, repo))
    result = run_tool(
        Tool("scanner", "install it"), sys.executable,
        [str(script), str(report), str(beside), str(outside), str(repo / "planted")],
        ctx, cwd=repo, out_dir=out,
    )  # fmt: skip
    assert result.returncode == 0, failure(result)
    done = json.loads(report.read_text(encoding="utf-8"))
    temp = Path(os.path.realpath(out / "tmp"))
    assert Path(os.path.realpath(done["TMPDIR"])) == temp
    assert Path(os.path.realpath(done["made"])).parent == temp
    assert done[str(beside)] is True
    assert done[str(outside)] is False
    assert done[str(repo / "planted")] is False
    assert not outside.exists()
