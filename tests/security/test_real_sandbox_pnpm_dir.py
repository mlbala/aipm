"""The v0.4 decisions, session 5, item 2, with the real pnpm and srt: a gate or prepare step that
runs pnpm in another directory (`-C`, `--dir`, `--prefix`, each also with `=`) never reads that
directory's `pnpm-workspace.yaml`.

Checked by hand on pnpm 10.34.9 (the progress doc, session 5, item 2): without aipm's variables,
`pnpm -C sub test` read `sub/pnpm-workspace.yaml`, installed when it said
`verifyDepsBeforeRun: install`, and ran its scripts through the file's `scriptShell`. With
`NPM_CONFIG_WORKSPACE_DIR` pinned to the worktree, pnpm read only the worktree root's file, for
every spelling; `--filter` and `-r` never read a package's own file.

Needs pnpm and srt on PATH (`.github/sandbox/node_modules/.bin` locally and in CI's sandbox
job, where `AIPM_REQUIRE_REAL_SRT=1` turns a missing tool into a failure). No network: the
dependency is a local tarball, and every profile is `none`.
"""

import dataclasses
import json
from pathlib import Path

import pytest

from aipm.config.schema import Config
from aipm.domain.errors import PolicyViolation
from aipm.domain.models import GateStatus
from aipm.gates.command_gate import run_command_gate, run_prepare
from aipm.gates.context import GateContext
from tests.security.test_gates import make_ctx
from tests.security.test_real_sandbox import (
    cache,  # noqa: F401 - the fixture
    need,
    tarball,
)

SPELLINGS = {
    "-C": ["-C", "sub"],
    "-C=": ["-C=sub"],
    "--dir": ["--dir", "sub"],
    "--dir=": ["--dir=sub"],
    "--prefix": ["--prefix", "sub"],
    "--prefix=": ["--prefix=sub"],
    "--filter": ["--filter", "app"],
    "-r": ["-r"],
}
"""Every way a gate can make pnpm run in `sub`. `--filter` and `-r` select it as a package of
the root's workspace."""

PROBE = """#!/bin/sh
echo ran > "{marker}" || exit 97
exec /bin/sh "$@"
"""
"""A `scriptShell` that leaves a marker in the worktree, which srt lets a gate write: pnpm runs
every script through it if it reads the file that names it. It fails the script when it cannot
write the marker, so a probe that ran is never missed."""

WROTE = "require('fs').writeFileSync('ran', 'x')"


def worktree(tmp_path: Path, run_cache: Path, *, sandboxed: bool, sub_settings: str) -> GateContext:
    """A worktree whose root `pnpm-workspace.yaml` lists the package `sub` (`app`, with one
    dependency), and whose `sub/pnpm-workspace.yaml` holds `sub_settings`."""
    ctx = make_ctx(tmp_path, runtime=need("srt") if sandboxed else None)
    sub = ctx.root / "sub"
    sub.mkdir()
    (ctx.root / "package.json").write_text(
        json.dumps({"name": "root", "version": "1.0.0", "private": True}), encoding="utf-8"
    )
    (ctx.root / "pnpm-workspace.yaml").write_text("packages:\n  - sub\n", encoding="utf-8")
    (sub / "package.json").write_text(
        json.dumps({
            "name": "app", "version": "1.0.0", "scripts": {"test": f'node -e "{WROTE}"'},
            "dependencies": {"dep": tarball(sub)},
        }),
        encoding="utf-8",
    )  # fmt: skip
    (sub / "pnpm-workspace.yaml").write_text(sub_settings, encoding="utf-8")
    return dataclasses.replace(ctx, package_cache=run_cache)


def configure(ctx: GateContext, *, gate: list[str] | None = None,
              prepare: list[str] | None = None) -> GateContext:  # fmt: skip
    data: dict[str, object] = {"allowed_executables": [r for r in (gate, prepare) if r]}
    if gate is not None:
        data["gates"] = {"unit": {"run": gate}}
    if prepare is not None:
        data["prepare"] = {"run": prepare}
    return dataclasses.replace(ctx, cfg=Config.model_validate(data))


def prepare_root(ctx: GateContext) -> None:
    """aipm's own prepare at the worktree root, as a build runs it before the gates."""
    pnpm = need("pnpm")
    ctx = configure(ctx, prepare=[pnpm, "install", "--offline", "--ignore-scripts"])
    outcome = run_prepare(ctx)
    assert outcome is not None
    assert outcome.result.status is GateStatus.PASS, outcome.full_output


@pytest.mark.parametrize("sandboxed", [True, False], ids=["srt", "no-srt"])
@pytest.mark.parametrize("flag", SPELLINGS.values(), ids=SPELLINGS.keys())
def test_a_gate_in_a_sub_directory_does_not_install(
    tmp_path: Path,
    cache: Path,  # noqa: F811 - the fixture
    flag: list[str],
    sandboxed: bool,
) -> None:
    """`sub/pnpm-workspace.yaml` asks to install before a script, and prepare never ran: the
    gate fails on the missing dependencies instead of installing them."""
    pnpm = need("pnpm")
    ctx = worktree(tmp_path, cache, sandboxed=sandboxed,
                   sub_settings="verifyDepsBeforeRun: install\n")  # fmt: skip
    ctx = configure(ctx, gate=[pnpm, *flag, "test"])
    outcome = run_command_gate("unit", ctx.cfg.gates["unit"], ctx, paths=[], required=True)
    assert outcome.result.status is GateStatus.FAIL, outcome.full_output
    assert "VERIFY_DEPS_BEFORE_RUN" in outcome.full_output, outcome.full_output
    assert not (ctx.root / "node_modules").exists()
    assert not (ctx.root / "sub" / "node_modules").exists()
    assert not (ctx.root / "sub" / "ran").exists()


@pytest.mark.parametrize("sandboxed", [True, False], ids=["srt", "no-srt"])
@pytest.mark.parametrize("flag", SPELLINGS.values(), ids=SPELLINGS.keys())
def test_a_gate_in_a_sub_directory_never_reads_its_settings(
    tmp_path: Path,
    cache: Path,  # noqa: F811 - the fixture
    flag: list[str],
    sandboxed: bool,
) -> None:
    """After prepare, the gate runs `sub`'s script, and not through the `scriptShell` that
    `sub/pnpm-workspace.yaml` names: pnpm did not read that file. Without the pin (checked by
    hand), `-C`, `--dir` and `--prefix` ran the probe. The variables aipm also sets cannot
    override `scriptShell`, so this shows the pin itself holds."""
    pnpm = need("pnpm")
    probe = tmp_path / "probe.sh"
    settings = f"scriptShell: {probe}\nverifyDepsBeforeRun: install\n"
    ctx = worktree(tmp_path, cache, sandboxed=sandboxed, sub_settings=settings)
    marker = ctx.root / "probe-ran"
    probe.write_text(PROBE.format(marker=marker), encoding="utf-8")
    probe.chmod(0o755)
    prepare_root(ctx)
    ctx = configure(ctx, gate=[pnpm, *flag, "test"])
    outcome = run_command_gate("unit", ctx.cfg.gates["unit"], ctx, paths=[], required=True)
    assert outcome.result.status is GateStatus.PASS, outcome.full_output
    assert (ctx.root / "sub" / "ran").exists(), outcome.full_output
    assert not marker.exists(), outcome.full_output


DIR_SETTINGS = ("storeDir", "cacheDir", "modulesDir", "virtualStoreDir")


@pytest.mark.parametrize("sandboxed", [True, False], ids=["srt", "no-srt"])
@pytest.mark.parametrize("flag", [f for f in SPELLINGS.values() if "sub" in "".join(f)],
                         ids=[k for k, f in SPELLINGS.items() if "sub" in "".join(f)])  # fmt: skip
def test_prepare_in_a_sub_directory_keeps_pnpm_files_where_cache_args_puts_them(
    tmp_path: Path,
    cache: Path,  # noqa: F811 - the fixture
    flag: list[str],
    sandboxed: bool,
) -> None:
    """`sub/pnpm-workspace.yaml` moves the store, the metadata cache, `node_modules` and the
    virtual store elsewhere, and asks to copy by hard link. Prepare `pnpm -C sub install` keeps
    them in the run's cache and the worktree: the store in the cache, copies, not links."""
    pnpm = need("pnpm")
    elsewhere = tmp_path / "elsewhere"
    settings = "".join(f"{key}: {elsewhere / key}\n" for key in DIR_SETTINGS)
    ctx = worktree(tmp_path, cache, sandboxed=sandboxed,
                   sub_settings=f"{settings}packageImportMethod: hardlink\n")  # fmt: skip
    ctx = configure(ctx, prepare=[pnpm, *flag, "install", "--offline", "--ignore-scripts"])
    outcome = run_prepare(ctx)
    assert outcome is not None
    assert outcome.result.status is GateStatus.PASS, outcome.full_output
    assert not elsewhere.exists()
    installed = sorted((ctx.root / "node_modules" / ".pnpm").rglob("index.js"))
    assert installed, "pnpm did not install into the worktree's virtual store"
    assert (ctx.root / "sub" / "node_modules" / "dep").is_symlink()
    stored = {f.stat().st_ino for f in (cache / "pnpm-store").rglob("*") if f.is_file()}
    assert stored, "pnpm did not use the run's store"
    for path in installed:
        assert path.stat().st_nlink == 1, path
        assert path.stat().st_ino not in stored, path


# ------------------------------------------------------------- a directory outside the worktree


def outside_package(tmp_path: Path, run_cache: Path, *, sandboxed: bool) -> GateContext:
    """A worktree whose committed root `pnpm-workspace.yaml` lists `../outside`, a package
    beside the worktree with no dependencies and its own installing workspace file. Prepare ran
    without srt, as setup."""
    ctx = make_ctx(tmp_path, runtime=None)
    outside = tmp_path / "outside"
    outside.mkdir()
    (ctx.root / "package.json").write_text(
        json.dumps({"name": "root", "version": "1.0.0", "private": True}), encoding="utf-8"
    )
    (ctx.root / "pnpm-workspace.yaml").write_text("packages:\n  - ../outside\n", encoding="utf-8")
    (outside / "package.json").write_text(
        json.dumps({"name": "out", "version": "1.0.0", "scripts": {"test": f'node -e "{WROTE}"'}}),
        encoding="utf-8",
    )
    (outside / "pnpm-workspace.yaml").write_text("verifyDepsBeforeRun: install\n", "utf-8")
    prepare_root(dataclasses.replace(ctx, package_cache=run_cache))
    runtime = need("srt") if sandboxed else None
    return dataclasses.replace(ctx, package_cache=run_cache, runtime=runtime)


OUTSIDE = {"relative": "../outside", "absolute": None}


@pytest.mark.parametrize("where", OUTSIDE.keys())
def test_srt_keeps_a_gate_run_outside_the_worktree_from_writing_there(
    tmp_path: Path,
    cache: Path,  # noqa: F811 - the fixture
    where: str,
) -> None:
    """`pnpm -C ../outside test` (or an absolute path) runs `outside`'s script only because the
    committed root file lists it as a package. Under srt the gate may write only its worktree
    and temp dir, so the script cannot write there."""
    pnpm = need("pnpm")
    ctx = outside_package(tmp_path, cache, sandboxed=True)
    target = OUTSIDE[where] or str(tmp_path / "outside")
    ctx = configure(ctx, gate=[pnpm, "-C", target, "test"])
    outcome = run_command_gate("unit", ctx.cfg.gates["unit"], ctx, paths=[], required=True)
    assert outcome.result.status is GateStatus.FAIL, outcome.full_output
    assert not (tmp_path / "outside" / "ran").exists(), outcome.full_output


@pytest.mark.xfail(
    strict=True,
    reason="open, needs the owner (session 5, item 2): without srt a gate runs and writes in a "
    "package the committed pnpm-workspace.yaml lists outside the worktree",
)
@pytest.mark.parametrize("where", OUTSIDE.keys())
def test_without_srt_a_gate_never_runs_outside_the_worktree(
    tmp_path: Path,
    cache: Path,  # noqa: F811 - the fixture
    where: str,
) -> None:
    """The open finding, pinned: without srt nothing confines the script, which ran in
    `outside` and wrote there (checked by hand on pnpm 10.34.9; `--filter out` and `-r` reach
    it too). Refusing the gate (exit 6) or keeping it from running there both pass."""
    pnpm = need("pnpm")
    ctx = outside_package(tmp_path, cache, sandboxed=False)
    target = OUTSIDE[where] or str(tmp_path / "outside")
    ctx = configure(ctx, gate=[pnpm, "-C", target, "test"])
    try:
        run_command_gate("unit", ctx.cfg.gates["unit"], ctx, paths=[], required=True)
    except PolicyViolation:
        pass
    assert not (tmp_path / "outside" / "ran").exists()
