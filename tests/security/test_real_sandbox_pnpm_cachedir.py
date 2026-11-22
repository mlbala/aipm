"""The v0.4 decisions, session 5, item 5, with the real pnpm and srt: prepare's `--cache-dir`
beats a committed `cacheDir`, so pnpm reads and writes its metadata cache only in the run's
`<cache>/pnpm-cache`, never where a repository's `pnpm-workspace.yaml` points.

The observer is the install prepare runs, `pnpm <cache_args> install --offline`, through
`run_prepare`. The project depends on a registry package, `aipm-probe-dep@1.0.0`, whose metadata
is planted in one cache dir; its tarball is nowhere. pnpm stops with `ERR_PNPM_NO_OFFLINE_TARBALL`
when the cache dir it reads holds the metadata, and with `ERR_PNPM_NO_OFFLINE_META` when it does
not, so the error says which dir pnpm read. A project with no dependencies, as in
`test_real_sandbox.py`, never touches the metadata cache offline.

Checked by hand on pnpm 10.34.9 (the progress doc, session 5, item 5): with the flag, metadata
only in the committed dir gave `NO_OFFLINE_META`; without it (`npm_config_cache_dir` alone),
`NO_OFFLINE_TARBALL`: the file beats the environment, so removing `--cache-dir` from `cache_args`
fails `test_a_committed_cache_dir_is_never_read`. `pnpm cache list` and `cache view` refuse
`--cache-dir` ("Unknown option") and list the user's own cache when it comes with the other
flags; `pnpm config get` refuses `--store-dir`. Neither can observe `cache_args`.

Needs pnpm and srt on PATH (`.github/sandbox/node_modules/.bin` locally and in CI's sandbox
job, where `AIPM_REQUIRE_REAL_SRT=1` turns a missing tool into a failure). No network: the
install is offline and fails before any download.
"""

import dataclasses
import json
from pathlib import Path

import pytest

from aipm.config.schema import Config
from aipm.domain.models import GateStatus
from aipm.gates.command_gate import run_prepare
from aipm.gates.context import GateContext
from tests.security.test_gates import make_ctx
from tests.security.test_real_sandbox import (
    cache,  # noqa: F401 - the fixture
    need,
)

DEP = "aipm-probe-dep"
META_DIRS = ("metadata-v1.3", "metadata-full-v1.3", "metadata-ff-v1.3")
"""pnpm 10's metadata cache layouts (abbreviated, full, full-filtered); planted in all three, so
whichever pnpm reads holds the entry. A pnpm that renamed them would fail every test closed."""
FOUND = "ERR_PNPM_NO_OFFLINE_TARBALL"
MISSING = "ERR_PNPM_NO_OFFLINE_META"

SANDBOXED = pytest.mark.parametrize("sandboxed", [True, False], ids=["srt", "no-srt"])
COMMITTED = pytest.mark.parametrize("spelling", ["relative", "absolute"])


def _plant(cache_dir: Path) -> list[Path]:
    """Metadata for `DEP` (a fake integrity, no tarball anywhere) in `cache_dir`."""
    meta = {
        "name": DEP,
        "dist-tags": {"latest": "1.0.0"},
        "versions": {
            "1.0.0": {
                "name": DEP,
                "version": "1.0.0",
                "dist": {
                    "tarball": f"https://registry.npmjs.org/{DEP}/-/{DEP}-1.0.0.tgz",
                    "integrity": "sha512-" + "A" * 86 + "==",
                },
            }
        },
        "cachedAt": 1_700_000_000_000,
    }
    planted = []
    for name in META_DIRS:
        target = cache_dir / name / "registry.npmjs.org" / f"{DEP}.json"
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(json.dumps(meta), encoding="utf-8")
        planted.append(target)
    return planted


def _tree(root: Path) -> dict[str, bytes]:
    return {str(p.relative_to(root)): p.read_bytes() for p in root.rglob("*") if p.is_file()}


def _ctx(tmp_path: Path, run_cache: Path, *, sandboxed: bool) -> GateContext:
    pnpm = need("pnpm")
    ctx = make_ctx(tmp_path, runtime=need("srt") if sandboxed else None)
    (ctx.root / "package.json").write_text(
        json.dumps({"name": "app", "version": "1.0.0", "dependencies": {DEP: "1.0.0"}}),
        encoding="utf-8",
    )
    cfg = Config.model_validate(
        {
            "allowed_executables": [[pnpm, "install"]],
            "prepare": {"run": [pnpm, "install", "--offline", "--ignore-scripts"]},
        }
    )
    return dataclasses.replace(ctx, cfg=cfg, package_cache=run_cache)


def _commit(ctx: GateContext, tmp_path: Path, spelling: str) -> Path:
    """Commit a `cacheDir` outside the worktree, under the test's own `tmp_path`."""
    target = tmp_path / ("outside-cache" if spelling == "relative" else "abs-cache")
    value = "../outside-cache" if spelling == "relative" else str(target)
    (ctx.root / "pnpm-workspace.yaml").write_text(f"cacheDir: {value}\n", encoding="utf-8")
    return target


def _prepare(ctx: GateContext) -> str:
    """Run prepare; it fails offline either way, and its pnpm error says which cache it read."""
    outcome = run_prepare(ctx)
    assert outcome is not None and outcome.result.status is GateStatus.FAIL, (
        outcome and outcome.full_output
    )
    output = outcome.full_output
    found, missing = FOUND in output, MISSING in output
    assert found != missing, output
    return FOUND if found else MISSING


# ------------------------------------------------------------------ a committed cacheDir


@SANDBOXED
@COMMITTED
def test_a_committed_cache_dir_is_never_read(
    tmp_path: Path,
    cache: Path,  # noqa: F811 - the fixture
    sandboxed: bool,
    spelling: str,
) -> None:
    """Metadata only in the committed dir: pnpm does not see it, and leaves the dir as it was.
    Without `--cache-dir` the file beats `npm_config_cache_dir` and pnpm finds it."""
    ctx = _ctx(tmp_path, cache, sandboxed=sandboxed)
    committed = _commit(ctx, tmp_path, spelling)
    _plant(committed)
    before = _tree(committed)
    assert _prepare(ctx) == MISSING
    assert _tree(committed) == before


@SANDBOXED
@COMMITTED
def test_the_flags_cache_dir_is_read_and_nothing_is_made_at_the_committed_path(
    tmp_path: Path,
    cache: Path,  # noqa: F811 - the fixture
    sandboxed: bool,
    spelling: str,
) -> None:
    ctx = _ctx(tmp_path, cache, sandboxed=sandboxed)
    committed = _commit(ctx, tmp_path, spelling)
    _plant(cache / "pnpm-cache")
    assert _prepare(ctx) == FOUND
    assert not committed.exists()


# ------------------------------------------------------------------ control: no committed file


@SANDBOXED
@pytest.mark.parametrize("planted", [True, False], ids=["metadata", "empty"])
def test_without_a_committed_cache_dir_the_flags_dir_decides(
    tmp_path: Path,
    cache: Path,  # noqa: F811 - the fixture
    sandboxed: bool,
    planted: bool,
) -> None:
    ctx = _ctx(tmp_path, cache, sandboxed=sandboxed)
    if planted:
        _plant(cache / "pnpm-cache")
    assert _prepare(ctx) == (FOUND if planted else MISSING)
