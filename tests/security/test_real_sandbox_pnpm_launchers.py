"""The v0.4 decisions, session 5, item 1, with the real pnpm and srt: a gate that runs pnpm's
own `pnpm.cjs` through `node` gets the same protection as one that runs `pnpm`.

Needs node, pnpm and srt on PATH (`.github/sandbox/node_modules/.bin` locally and in CI's
sandbox job, where `AIPM_REQUIRE_REAL_SRT=1` turns a missing tool into a failure). No network:
the dependency is a local tarball, and the gate's network profile is `none`.
"""

import dataclasses
import json
from pathlib import Path

import pytest

from aipm.config.schema import Config
from aipm.domain.errors import PolicyViolation
from aipm.domain.models import GateStatus
from aipm.gates.command_gate import run_command_gate
from aipm.gates.context import GateContext
from tests.security.test_gates import make_ctx
from tests.security.test_real_sandbox import (
    cache,  # noqa: F401 - the fixture
    need,
    tarball,
)


def node_pnpm_ctx(tmp_path: Path, run_cache: Path, *, sandboxed: bool, setting: str) -> GateContext:
    """A gate `node <pnpm.cjs> test` in a worktree whose dependency is not installed and whose
    `pnpm-workspace.yaml` sets `verifyDepsBeforeRun: <setting>`."""
    node = need("node")
    pnpm_cjs = str(Path(need("pnpm")).resolve())
    assert pnpm_cjs.endswith("pnpm.cjs"), pnpm_cjs
    ctx = make_ctx(tmp_path, runtime=need("srt") if sandboxed else None)
    (ctx.root / "package.json").write_text(
        json.dumps({
            "name": "app", "version": "1.0.0", "scripts": {"test": "node -e 0"},
            "dependencies": {"dep": tarball(ctx.root)},
        }),
        encoding="utf-8",
    )  # fmt: skip
    (ctx.root / "pnpm-workspace.yaml").write_text(
        f"verifyDepsBeforeRun: {setting}\n", encoding="utf-8"
    )
    run = [node, pnpm_cjs, "test"]
    cfg = Config.model_validate({"allowed_executables": [run], "gates": {"unit": {"run": run}}})
    return dataclasses.replace(ctx, cfg=cfg, package_cache=run_cache)


@pytest.mark.parametrize("sandboxed", [True, False], ids=["srt", "no-srt"])
def test_node_running_pnpm_is_refused_when_the_workspace_file_installs(
    tmp_path: Path,
    cache: Path,  # noqa: F811 - the fixture
    sandboxed: bool,
) -> None:
    """Checked by hand on pnpm 10.34.9: `node pnpm.cjs test` installed first when the file said
    `install` and nothing overrode it. The gate never starts."""
    ctx = node_pnpm_ctx(tmp_path, cache, sandboxed=sandboxed, setting="install")
    with pytest.raises(PolicyViolation, match="verifyDepsBeforeRun"):
        run_command_gate("unit", ctx.cfg.gates["unit"], ctx, paths=[], required=True)
    assert not (ctx.root / "node_modules").exists()


@pytest.mark.parametrize("sandboxed", [True, False], ids=["srt", "no-srt"])
def test_node_running_pnpm_runs_without_installing(
    tmp_path: Path,
    cache: Path,  # noqa: F811 - the fixture
    sandboxed: bool,
) -> None:
    """With `error` the gate runs, and pnpm fails on the dependencies prepare never installed
    instead of installing them."""
    ctx = node_pnpm_ctx(tmp_path, cache, sandboxed=sandboxed, setting="error")
    outcome = run_command_gate("unit", ctx.cfg.gates["unit"], ctx, paths=[], required=True)
    assert outcome.result.status is GateStatus.FAIL, outcome.full_output
    assert "VERIFY_DEPS_BEFORE_RUN" in outcome.full_output, outcome.full_output
    assert not (ctx.root / "node_modules").exists()
