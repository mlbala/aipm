"""The v0.4 decisions, session 5, item 2: `pnpm -C <dir>` and another directory's settings.

A user-configured gate or prepare step can run pnpm in another directory (`-C`, `--dir`,
`--prefix`, each also with `=`). aipm reads only the worktree root's `pnpm-workspace.yaml`.
Checked by hand on pnpm 10.34.9 (the progress doc, session 5, item 2): with
`NPM_CONFIG_WORKSPACE_DIR` pinned to the worktree, pnpm reads that root file and never the other
directory's, for every spelling; without the pin it read `sub/pnpm-workspace.yaml`, installed
when it asked to, and ran scripts through its `scriptShell`. So no code changed: these tests pin
that every spelling still reaches pnpm with the pin to the root, and is checked against the
root's file. `test_real_sandbox_pnpm_dir.py` runs the real pnpm.

The recorder is written to the test's own directory, as item 1's are, not to `tests/fakes/bin/`.
"""

import dataclasses
import json
import sys
from pathlib import Path

import pytest

from aipm.config.schema import Config
from aipm.domain.errors import ExitCode, PolicyViolation
from aipm.domain.models import GateStatus
from aipm.execution.package_cache import lockfile_args
from aipm.gates.command_gate import run_command_gate, run_prepare
from aipm.gates.context import GateContext
from aipm.security.command_policy import CommandPolicy, Stage, check_argv
from tests.security.test_gates import make_ctx

SPELLINGS = {
    "-C": ["-C", "sub"],
    "-C=": ["-C=sub"],
    "--dir": ["--dir", "sub"],
    "--dir=": ["--dir=sub"],
    "--prefix": ["--prefix", "sub"],
    "--prefix=": ["--prefix=sub"],
}

VARIABLES = (
    "NPM_CONFIG_WORKSPACE_DIR",
    "npm_config_verify_deps_before_run",
    "pnpm_config_verify_deps_before_run",
)

RECORDER = """#!{python}
import json, os, sys
with open({log!r}, "w") as out:
    json.dump({{"argv": sys.argv[1:], "env": [os.environ.get(n, "unset") for n in {names!r}]}}, out)
"""


def pnpm_recorder(tmp_path: Path) -> tuple[str, Path]:
    """An executable called `pnpm` that records its arguments and the three variables."""
    log = tmp_path / "pnpm.log"
    bin_dir = tmp_path / "pnpm-bin"
    bin_dir.mkdir()
    program = bin_dir / "pnpm"
    program.write_text(
        RECORDER.format(python=sys.executable, log=str(log), names=VARIABLES), encoding="utf-8"
    )
    program.chmod(0o755)
    return str(program), log


def ctx_for(tmp_path: Path, *, gate: list[str], prepare: list[str] | None = None) -> GateContext:
    ctx = make_ctx(tmp_path)
    (ctx.root / "sub").mkdir()
    data: dict[str, object] = {"allowed_executables": [gate], "gates": {"unit": {"run": gate}}}
    if prepare is not None:
        data["allowed_executables"] = [gate, prepare]
        data["prepare"] = {"run": prepare}
    return dataclasses.replace(
        ctx, cfg=Config.model_validate(data), package_cache=tmp_path / "run-cache"
    )


def run_unit(ctx: GateContext) -> GateStatus:
    outcome = run_command_gate("unit", ctx.cfg.gates["unit"], ctx, paths=[], required=True)
    return outcome.result.status


@pytest.mark.parametrize("flag", SPELLINGS.values(), ids=SPELLINGS.keys())
@pytest.mark.parametrize("stage", ["gate", "prepare"])
def test_the_policy_accepts_every_directory_spelling(flag: list[str], stage: Stage) -> None:
    """The real-tool tests must reach pnpm: no spelling is refused by the command policy, which
    this item does not change."""
    argv = ["pnpm", *flag, "install" if stage == "prepare" else "test"]
    policy = CommandPolicy(allowed_prefixes=(tuple(argv),))
    assert list(check_argv(argv, policy, stage=stage)) == argv


@pytest.mark.parametrize("flag", SPELLINGS.values(), ids=SPELLINGS.keys())
def test_a_gate_in_a_sub_directory_is_pinned_to_the_worktree_root(
    tmp_path: Path, flag: list[str]
) -> None:
    """`NPM_CONFIG_WORKSPACE_DIR` names the worktree root, not the directory the flag names:
    that is what keeps pnpm from reading `sub/pnpm-workspace.yaml` (checked by hand)."""
    program, log = pnpm_recorder(tmp_path)
    ctx = ctx_for(tmp_path, gate=[program, *flag, "test"])
    assert run_unit(ctx) is GateStatus.PASS
    got = json.loads(log.read_text(encoding="utf-8"))
    assert got == {"argv": [*flag, "test"], "env": [str(ctx.root), "error", "error"]}


@pytest.mark.parametrize("flag", SPELLINGS.values(), ids=SPELLINGS.keys())
def test_prepare_in_a_sub_directory_gets_the_cache_flags_first(
    tmp_path: Path, flag: list[str]
) -> None:
    """`cache_args` and `lockfile_args` go right after `pnpm`, before the directory flag, and
    the pin and the lockfile directory (`.`, prepare's working directory) are the worktree root,
    not the directory the flag names."""
    program, log = pnpm_recorder(tmp_path)
    ctx = ctx_for(tmp_path, gate=[program, "test"], prepare=[program, *flag, "install"])
    outcome = run_prepare(ctx)
    assert outcome is not None and outcome.result.status is GateStatus.PASS, outcome
    got = json.loads(log.read_text(encoding="utf-8"))
    cache = ctx.package_dir
    assert got["argv"] == [
        f"--store-dir={cache / 'pnpm-store'}",
        "--package-import-method=copy",
        f"--cache-dir={cache / 'pnpm-cache'}",
        "--virtual-store-dir=node_modules/.pnpm",
        "--modules-dir=node_modules",
        "--lockfile-dir=.",
        *flag,
        "install",
    ]
    assert got["env"] == [str(ctx.root), "error", "error"]


@pytest.mark.parametrize("flag", SPELLINGS.values(), ids=SPELLINGS.keys())
def test_a_root_file_that_installs_refuses_every_spelling(tmp_path: Path, flag: list[str]) -> None:
    """The file pnpm reads under the pin is the root's, and that is the one aipm checks."""
    program, log = pnpm_recorder(tmp_path)
    ctx = ctx_for(tmp_path, gate=[program, *flag, "test"])
    (ctx.root / "pnpm-workspace.yaml").write_text("verifyDepsBeforeRun: install\n", "utf-8")
    with pytest.raises(PolicyViolation, match="verifyDepsBeforeRun") as info:
        run_unit(ctx)
    assert info.value.exit_code is ExitCode.SECURITY_VIOLATION
    assert not log.exists()


@pytest.mark.parametrize("flag", SPELLINGS.values(), ids=SPELLINGS.keys())
def test_a_sub_directory_file_is_not_checked_because_pnpm_never_reads_it(
    tmp_path: Path, flag: list[str]
) -> None:
    """The smallest fix the hand check allows: none. Under the pin pnpm ignores
    `sub/pnpm-workspace.yaml` (its `install` and its `scriptShell`), so refusing the gate for it
    would fail repositories whose packages carry their own file, for nothing."""
    program, log = pnpm_recorder(tmp_path)
    ctx = ctx_for(tmp_path, gate=[program, *flag, "test"])
    (ctx.root / "sub" / "pnpm-workspace.yaml").write_text("verifyDepsBeforeRun: install\n", "utf-8")
    assert run_unit(ctx) is GateStatus.PASS
    assert log.exists()


def test_only_pnpm_gets_the_lockfile_flag() -> None:
    """Review of item 2: a committed `lockfile-dir` moved prepare's lockfile and virtual store
    outside the worktree; the flag beats `.npmrc` and `pnpm-workspace.yaml` (checked by hand on
    pnpm 10.34.9)."""
    assert lockfile_args("/opt/bin/pnpm") == ("--lockfile-dir=.",)
    for other in ("npm", "uv", "go", "cargo", "/usr/bin/python3", "pnpx", "corepack"):
        assert lockfile_args(other) == ()
