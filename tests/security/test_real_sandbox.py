"""The run's package cache under the real `srt` (ADR-0031, v0.3 rec 3).

These tests need the real sandbox runtime, and some need Go, Cargo or pnpm. Without them they
skip; CI's `sandbox` job sets `AIPM_REQUIRE_REAL_SRT=1`, which turns every such skip into a
failure, so a broken install cannot pass as "skipped". They use no network: every process runs
under the `none` network profile, and the toolchains work offline on a project with no
dependencies.

Each test builds a profile with `profile_for`, as the build does, and runs through `run_safe`.
"""

import dataclasses
import json
import os
import shutil
import sys
import tarfile
from pathlib import Path

import pytest

from aipm.config.schema import Config
from aipm.domain.models import GateStatus
from aipm.domain.models.gates import NetworkProfile
from aipm.execution import package_cache
from aipm.execution.package_cache import cache_env, run_cache
from aipm.execution.process import ProcessResult, build_env, run_safe
from aipm.execution.sandbox import (
    CARGO_DIR,
    PREPARE_WRITABLE,
    ProcessKind,
    ProfilePaths,
    launcher_for,
    profile_for,
)
from aipm.gates.command_gate import run_prepare
from aipm.security.network import NetworkPolicy
from tests.conftest import REPO_ROOT
from tests.security.test_gates import make_ctx

STUB_BIN = REPO_ROOT / "tests" / "fakes" / "bin"
REQUIRED = os.environ.get("AIPM_REQUIRE_REAL_SRT") == "1"
TIMEOUT_S = 600.0

WRITER = """
import json, sys
done = {}
for target in sys.argv[2:]:
    try:
        with open(target, "w") as handle:
            handle.write("planted")
        done[target] = True
    except OSError:
        done[target] = False
with open(sys.argv[1], "w") as out:
    json.dump(done, out)
"""
"""Tries to write each path it is given; records which writes the sandbox let through."""


def need(tool: str) -> str:
    """The real `tool` from PATH: skipped without it, or failed when CI requires it."""
    found = shutil.which(tool)
    if found is None or Path(found).parent == STUB_BIN:
        message = f"needs the real {tool} on PATH"
        if REQUIRED:
            pytest.fail(f"{message} (AIPM_REQUIRE_REAL_SRT=1)")
        pytest.skip(message)
    return found


@pytest.fixture
def cache(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    """A run's package cache, made by `run_cache` under the test's own cache root."""
    repo = tmp_path / "repo"
    repo.mkdir()
    monkeypatch.setattr(package_cache, "cache_root", lambda: tmp_path / "cache-root")
    return run_cache(repo, "r-20261115-1200-abcd", home=Path.home())


def run(
    kind: ProcessKind,
    argv: list[str],
    *,
    workspace: Path,
    cache: Path,
    extra: dict[str, str] | None = None,
) -> ProcessResult:
    """Run `argv` in `workspace` under the real `srt`, with `kind`'s profile and no network."""
    srt = need("srt")
    temp = workspace.parent / f"{workspace.name}-temp"
    temp.mkdir(mode=0o700, exist_ok=True)
    paths = ProfilePaths(workspace=workspace, temp_dir=temp, home=Path.home(), package_cache=cache)
    launcher = launcher_for(srt, workspace)
    profile = profile_for(kind, NetworkPolicy(NetworkProfile.NONE), paths, runtime=launcher)
    env = build_env(extra={"TMPDIR": str(temp), **(extra or {})})
    return run_safe(
        argv, cwd=workspace, env=env, timeout_s=TIMEOUT_S, max_output_bytes=200_000,
        sandbox=profile,
    )  # fmt: skip


def writes(
    kind: ProcessKind, targets: list[Path], *, tmp_path: Path, cache: Path
) -> dict[Path, bool]:
    """Which of `targets` a process of `kind` could write."""
    workspace = tmp_path / "ws"
    workspace.mkdir(exist_ok=True)
    script = tmp_path / "writer.py"
    script.write_text(WRITER, encoding="utf-8")
    report = workspace / "report.json"
    argv = [sys.executable, str(script), str(report), *map(str, targets)]
    result = run(kind, argv, workspace=workspace, cache=cache)
    assert result.returncode == 0, result.stderr.decode(errors="replace")
    done = json.loads(report.read_text(encoding="utf-8"))
    return {Path(k): v for k, v in done.items()}


def failure(result: ProcessResult) -> str:
    return (result.stdout + result.stderr).decode("utf-8", errors="replace")[-4000:]


# ------------------------------------------------------------------ the write rules


def test_prepare_writes_only_the_listed_cache_paths(tmp_path: Path, cache: Path) -> None:
    """ADR-0031: prepare may write each package manager's directory, never the cache root or
    Cargo's settings and `bin/`, which every later task's gates would read or run."""
    allowed = [cache / rel / "probe" for rel in PREPARE_WRITABLE if "." not in rel.rsplit("/")[-1]]
    denied = [
        cache / "planted",
        cache / CARGO_DIR / "config.toml",
        cache / CARGO_DIR / "bin" / "cargo-planted",
        cache / CARGO_DIR / "credentials.toml",
    ]
    (cache / CARGO_DIR / "bin").mkdir(exist_ok=True)
    done = writes(ProcessKind.PREPARE, allowed + denied, tmp_path=tmp_path, cache=cache)
    assert all(done[p] for p in allowed), {p: v for p, v in done.items() if p in allowed}
    assert not any(done[p] for p in denied), {p: v for p, v in done.items() if p in denied}


def test_gates_may_not_write_the_run_cache(tmp_path: Path, cache: Path) -> None:
    """ADR-0031: only prepare writes the cache, so a gate cannot change what the next task's
    gates compile. The gate may still write its worktree."""
    targets = [cache / rel / "probe" for rel in ("uv", "go-mod", f"{CARGO_DIR}/registry")]
    own = tmp_path / "ws" / "own-file"
    done = writes(ProcessKind.GATE, [*targets, own], tmp_path=tmp_path, cache=cache)
    assert done[own]
    assert not any(done[p] for p in targets), done


# ------------------------------------------------------------------ the toolchains


def test_pnpm_reads_the_store_and_import_method_from_the_environment(
    tmp_path: Path, cache: Path
) -> None:
    """ADR-0031, unverified until now: pnpm uses `npm_config_store_dir` and copies instead of
    hard-linking, also when a repository `.npmrc` says otherwise (the environment wins)."""
    pnpm = need("pnpm")
    workspace = tmp_path / "ws"
    workspace.mkdir()
    (workspace / "package.json").write_text('{"name": "x", "version": "1.0.0"}\n', "utf-8")
    (workspace / ".npmrc").write_text(
        f"store-dir={tmp_path / 'elsewhere'}\npackage-import-method=hardlink\n", "utf-8"
    )
    extra = cache_env(pnpm, cache, tmp_path)
    store = run(ProcessKind.PREPARE, [pnpm, "store", "path"], workspace=workspace, cache=cache,
                extra=extra)  # fmt: skip
    assert store.returncode == 0, failure(store)
    assert Path(store.stdout.decode().strip()).parent == cache / "pnpm-store"
    method = run(ProcessKind.PREPARE, [pnpm, "config", "get", "package-import-method"],
                 workspace=workspace, cache=cache, extra=extra)  # fmt: skip
    assert method.returncode == 0, failure(method)
    assert method.stdout.decode().strip() == "clone-or-copy"


DEP_PACKAGE = {"name": "dep", "version": "1.0.0", "main": "index.js"}


def tarball(directory: Path) -> str:
    """A local npm package tarball, so pnpm installs through its store without the network."""
    source = directory.parent / "dep-src" / "package"
    source.mkdir(parents=True)
    (source / "package.json").write_text(json.dumps(DEP_PACKAGE), encoding="utf-8")
    (source / "index.js").write_text("module.exports = 1;\n", encoding="utf-8")
    with tarfile.open(directory / "dep-1.0.0.tgz", "w:gz") as archive:
        archive.add(source, arcname="package")
    return "file:dep-1.0.0.tgz"


@pytest.mark.parametrize(
    ("name", "text"),
    [
        ("pnpm-workspace.yaml", "storeDir: {elsewhere}\npackageImportMethod: hardlink\n"),
        ("pnpm-workspace.yaml", "packageImportMethod: hardlink\n"),
        (".npmrc", "store-dir={elsewhere}\npackage-import-method=hardlink\n"),
    ],
    ids=["workspace-store-and-hardlink", "workspace-hardlink", "npmrc-store-and-hardlink"],
)
def test_a_committed_pnpm_setting_cannot_share_files_with_the_run_store(
    tmp_path: Path, cache: Path, name: str, text: str
) -> None:
    """Session 3: pnpm 10 let a committed `pnpm-workspace.yaml` override the run cache's store
    and import method. With `hardlink`, each task's `node_modules` shared inodes with the run's
    store, so a write in one worktree changed what a later task's gates ran (M-2 again). aipm
    now passes `--store-dir` and `--package-import-method=copy`, which win over the file; an
    `.npmrc` is covered the same way. Runs aipm's own prepare under the real srt."""
    pnpm = need("pnpm")
    srt = need("srt")
    ctx = make_ctx(tmp_path, runtime=srt)
    elsewhere = tmp_path / "elsewhere"
    (ctx.root / "package.json").write_text(
        json.dumps({"name": "app", "version": "1.0.0", "dependencies": {"dep": tarball(ctx.root)}}),
        encoding="utf-8",
    )
    (ctx.root / name).write_text(text.format(elsewhere=elsewhere), encoding="utf-8")
    cfg = Config.model_validate(
        {
            "allowed_executables": [[pnpm, "install"]],
            "prepare": {"run": [pnpm, "install", "--offline", "--ignore-scripts"]},
        }
    )
    ctx = dataclasses.replace(ctx, cfg=cfg, package_cache=cache)
    outcome = run_prepare(ctx)
    assert outcome is not None and outcome.result.status is GateStatus.PASS, outcome.full_output
    installed = sorted((ctx.root / "node_modules" / ".pnpm").rglob("index.js"))
    assert installed
    store = cache / "pnpm-store"
    stored = {f.stat().st_ino for f in store.rglob("*") if f.is_file()}
    assert stored, "pnpm did not use the run's store"
    for path in installed:
        assert path.stat().st_nlink == 1, path
        assert path.stat().st_ino not in stored, path
    assert not elsewhere.exists()


def test_go_vet_runs_with_a_read_only_module_cache(tmp_path: Path, cache: Path) -> None:
    """ADR-0031, unverified until now: a gate's `GOMODCACHE` is the run's, which gates cannot
    write; `go vet` must still work, with its build cache in the attempt's temp dir."""
    go = need("go")
    workspace = tmp_path / "ws"
    workspace.mkdir()
    (workspace / "go.mod").write_text("module example.com/m\n\ngo 1.21\n", "utf-8")
    (workspace / "main.go").write_text(
        'package main\n\nimport "fmt"\n\nfunc main() { fmt.Println("ok") }\n', "utf-8"
    )
    temp = tmp_path / "ws-temp"
    extra = {**cache_env(go, cache, temp), "GOTOOLCHAIN": "local", "GOFLAGS": "-mod=readonly"}
    result = run(ProcessKind.GATE, [go, "vet", "./..."], workspace=workspace, cache=cache,
                 extra=extra)  # fmt: skip
    assert result.returncode == 0, failure(result)


def test_cargo_runs_offline_with_a_read_only_cargo_home(tmp_path: Path, cache: Path) -> None:
    """ADR-0031, unverified until now: a gate's `CARGO_HOME` is the run's, which gates cannot
    write (Cargo takes a lock in `.package-cache`); an offline build and test must still
    work on a crate with no dependencies."""
    cargo = need("cargo")
    workspace = tmp_path / "ws"
    (workspace / "src").mkdir(parents=True)
    (workspace / "Cargo.toml").write_text(
        '[package]\nname = "m"\nversion = "0.1.0"\nedition = "2021"\n', "utf-8"
    )
    (workspace / "src" / "lib.rs").write_text(
        "pub fn two() -> u8 { 2 }\n\n#[test]\nfn it_is_two() { assert_eq!(two(), 2); }\n", "utf-8"
    )
    extra = cache_env(cargo, cache, tmp_path)
    if "RUSTUP_HOME" in os.environ:  # the runner's toolchain, read-only
        extra["RUSTUP_HOME"] = os.environ["RUSTUP_HOME"]
    result = run(ProcessKind.GATE, [cargo, "test", "--offline"], workspace=workspace,
                 cache=cache, extra=extra)  # fmt: skip
    assert result.returncode == 0, failure(result)
