"""The v0.4 decisions, session 5, item 1: pnpm reached through another launcher.

Session 4 gave a gate whose `argv[0]` is `pnpm` the `verifyDepsBeforeRun=error` variables and a
refusal when `pnpm-workspace.yaml` asks pnpm to install before a script. A gate reaching pnpm
another way (`corepack pnpm test`, `node …/pnpm.cjs test`, an npm script that calls `pnpm`)
got neither. Checked by hand on pnpm 10.34.9, npm 11.5.2 and corepack 0.32.0 (the progress doc,
session 5, item 1).

The recorders here are written to the test's own directory, as session 4's are, not to
`tests/fakes/bin/`: a stub named `node`, `npm` or `go` there would shadow the real tools for
every test that puts that directory on PATH.
"""

import dataclasses
import sys
from pathlib import Path

import pytest

from aipm.config.schema import Config
from aipm.domain.errors import ExitCode, PolicyViolation
from aipm.domain.models import GateStatus
from aipm.execution.package_cache import pnpm_env, pnpm_guard_env
from aipm.gates.command_gate import (
    reaches_pnpm,
    refuse_pnpm_install_before_run,
    run_command_gate,
    run_prepare,
)
from aipm.gates.context import GateContext
from aipm.security.command_policy import CommandPolicy, check_argv
from tests.security.test_gates import make_ctx

VARIABLES = (
    "NPM_CONFIG_WORKSPACE_DIR",
    "npm_config_verify_deps_before_run",
    "pnpm_config_verify_deps_before_run",
)

RECORDER = """#!{python}
import os
with open({log!r}, "a") as out:
    for name in {names!r}:
        out.write(os.environ.get(name, "unset") + "\\n")
"""

PNPM_CJS = "node_modules/pnpm/bin/pnpm.cjs"


def recorder(tmp_path: Path, name: str) -> tuple[str, Path]:
    """An executable called `name` that writes the three variables it got to a log."""
    log = tmp_path / f"{name}.log"
    bin_dir = tmp_path / f"{name}-bin"
    bin_dir.mkdir()
    program = bin_dir / name
    program.write_text(
        RECORDER.format(python=sys.executable, log=str(log), names=VARIABLES), encoding="utf-8"
    )
    program.chmod(0o755)
    return str(program), log


def gate_ctx(tmp_path: Path, run: list[str], *, prepare: list[str] | None = None) -> GateContext:
    """A context with one gate `unit` running `run`, and a prepare step when given."""
    ctx = make_ctx(tmp_path)
    data: dict[str, object] = {"allowed_executables": [run], "gates": {"unit": {"run": run}}}
    if prepare is not None:
        data["allowed_executables"] = [run, prepare]
        data["prepare"] = {"run": prepare}
    cfg = Config.model_validate(data)
    return dataclasses.replace(ctx, cfg=cfg, package_cache=tmp_path / "run-cache")


def run_unit(ctx: GateContext) -> GateStatus:
    outcome = run_command_gate("unit", ctx.cfg.gates["unit"], ctx, paths=[], required=True)
    return outcome.result.status


# ------------------------------------------------------------------ the environment


@pytest.mark.parametrize(
    ("name", "rest"),
    [
        ("corepack", ["pnpm", "test"]),
        ("node", [PNPM_CJS, "test"]),
        ("uv", ["run", "pytest"]),
        ("go", ["test", "./..."]),
        ("pnpm", ["test"]),
    ],
)
def test_every_gate_gets_the_pnpm_variables_whatever_starts_it(
    tmp_path: Path, name: str, rest: list[str]
) -> None:
    """The environment reaches pnpm through any launcher (checked by hand: `corepack pnpm`,
    `node …/pnpm.cjs` and an npm script all made pnpm fail rather than install), and uv
    ignores the variables (checked by hand on uv 0.13.6)."""
    program, log = recorder(tmp_path, name)
    ctx = gate_ctx(tmp_path, [program, *rest])
    assert run_unit(ctx) is GateStatus.PASS
    assert log.read_text(encoding="utf-8").splitlines() == [str(ctx.root), "error", "error"]


def test_an_npm_gate_gets_only_the_variable_npm_does_not_warn_about(tmp_path: Path) -> None:
    """npm 11.5.2 warns `Unknown env config "workspace-dir"` and `"verify-deps-before-run"`
    for the two `npm_config_` spellings, and says they will stop working in its next major
    version; it says nothing about `pnpm_config_…`, which still beats `pnpm-workspace.yaml` in a
    script that calls pnpm. A committed `.npmrc` is the gap (SECURITY.md R-26)."""
    program, log = recorder(tmp_path, "npm")
    ctx = gate_ctx(tmp_path, [program, "test"])
    assert run_unit(ctx) is GateStatus.PASS
    assert log.read_text(encoding="utf-8").splitlines() == ["unset", "unset", "error"]


@pytest.mark.parametrize(("name", "expected"), [("uv", 3), ("npm", 1), ("pnpm", 3)])
def test_prepare_gets_the_same_variables(tmp_path: Path, name: str, expected: int) -> None:
    program, log = recorder(tmp_path, name)
    ctx = gate_ctx(tmp_path, [program, "test"], prepare=[program, "install"])
    outcome = run_prepare(ctx)
    assert outcome is not None and outcome.result.status is GateStatus.PASS, outcome
    got = log.read_text(encoding="utf-8").splitlines()
    assert sum(value != "unset" for value in got) == expected, got
    assert got[2] == "error"


def test_the_guard_variables_by_program(tmp_path: Path) -> None:
    full = {
        "NPM_CONFIG_WORKSPACE_DIR": str(tmp_path),
        "npm_config_verify_deps_before_run": "error",
        "pnpm_config_verify_deps_before_run": "error",
    }
    for program in ("/opt/bin/pnpm", "corepack", "node22", "uv", "go", "cargo", "/usr/bin/make"):
        assert pnpm_guard_env(program, tmp_path) == full
    for program in ("npm", "/usr/local/bin/npm", "NPM"):
        assert pnpm_guard_env(program, tmp_path) == {"pnpm_config_verify_deps_before_run": "error"}
    assert pnpm_env("/opt/bin/pnpm", tmp_path) == full  # pnpm's own set is unchanged


# ------------------------------------------------------------------ the refusal


@pytest.mark.parametrize(
    "argv",
    [
        ["/opt/bin/pnpm", "test"],
        ["corepack", "pnpm", "test"],
        ["/usr/local/bin/corepack", "pnpm@10.34.9", "test"],
        ["node", PNPM_CJS, "test"],
        ["/usr/bin/node22", "--no-warnings", "/opt/pnpm/dist/pnpm.mjs", "run", "x"],
        ["node", "/x/PNPM.JS", "test"],
        ["time", "pnpm", "test"],
    ],
)
def test_argv_that_reaches_pnpm(argv: list[str]) -> None:
    assert reaches_pnpm(argv)


@pytest.mark.parametrize(
    "argv",
    [
        ["npm", "test"],
        ["uv", "run", "pytest", "tests/pnpm_test.py"],
        ["node", "scripts/pnpm-check.cjs"],
        ["corepack", "yarn", "test"],
        ["go", "test", "./..."],
    ],
)
def test_argv_that_does_not_reach_pnpm(argv: list[str]) -> None:
    assert not reaches_pnpm(argv)


INSTALLING = {
    "install": "verifyDepsBeforeRun: install\n",
    "prompt": "verify-deps-before-run: prompt\n",
    "expanded-key": '"${AIPM_NOPE:-verifyDepsBeforeRun}": error\n',
}


@pytest.mark.parametrize("text", INSTALLING.values(), ids=INSTALLING.keys())
@pytest.mark.parametrize(
    "argv", [["corepack", "pnpm", "test"], ["node", PNPM_CJS, "test"]], ids=["corepack", "node"]
)
def test_a_launcher_gate_is_refused_when_the_workspace_file_installs(
    tmp_path: Path, argv: list[str], text: str
) -> None:
    root = tmp_path / "repo"
    root.mkdir()
    (root / "pnpm-workspace.yaml").write_text(text, encoding="utf-8")
    with pytest.raises(PolicyViolation, match="install dependencies first") as info:
        refuse_pnpm_install_before_run(argv[0], root, argv[1:])
    assert info.value.exit_code is ExitCode.SECURITY_VIOLATION


@pytest.mark.parametrize(
    "argv", [["corepack", "pnpm", "test"], ["node", PNPM_CJS, "test"]], ids=["corepack", "node"]
)
@pytest.mark.parametrize("kind", ["directory", "link", "unparsable"])
def test_a_launcher_gate_is_refused_when_the_workspace_file_cannot_be_checked(
    tmp_path: Path, argv: list[str], kind: str
) -> None:
    root = tmp_path / "repo"
    root.mkdir()
    target = root / "pnpm-workspace.yaml"
    if kind == "directory":
        target.mkdir()
    elif kind == "link":
        (tmp_path / "real.yaml").write_text("verifyDepsBeforeRun: error\n", encoding="utf-8")
        target.symlink_to(tmp_path / "real.yaml")
    else:
        target.write_text("key: [unclosed\n", encoding="utf-8")
    with pytest.raises(PolicyViolation, match="cannot be checked"):
        refuse_pnpm_install_before_run(argv[0], root, argv[1:])


@pytest.mark.parametrize("text", ["verifyDepsBeforeRun: error\n", None], ids=["error", "no-file"])
@pytest.mark.parametrize(
    "argv", [["corepack", "pnpm", "test"], ["node", PNPM_CJS, "test"]], ids=["corepack", "node"]
)
def test_a_launcher_gate_runs_with_a_safe_or_no_workspace_file(
    tmp_path: Path, argv: list[str], text: str | None
) -> None:
    root = tmp_path / "repo"
    root.mkdir()
    if text is not None:
        (root / "pnpm-workspace.yaml").write_text(text, encoding="utf-8")
    refuse_pnpm_install_before_run(argv[0], root, argv[1:])


def test_a_gate_that_does_not_reach_pnpm_is_not_checked(tmp_path: Path) -> None:
    """An unreadable file only matters to pnpm: a uv or npm gate is not refused for it."""
    root = tmp_path / "repo"
    root.mkdir()
    (root / "pnpm-workspace.yaml").mkdir()
    refuse_pnpm_install_before_run("uv", root, ["run", "pytest"])
    refuse_pnpm_install_before_run("npm", root, ["test"])


@pytest.mark.parametrize(
    ("name", "rest"), [("corepack", ["pnpm", "test"]), ("node", [PNPM_CJS, "test"])]
)
def test_a_launcher_gate_with_an_installing_workspace_file_never_starts(
    tmp_path: Path, name: str, rest: list[str]
) -> None:
    program, log = recorder(tmp_path, name)
    ctx = gate_ctx(tmp_path, [program, *rest])
    (ctx.root / "pnpm-workspace.yaml").write_text(
        "verifyDepsBeforeRun: install\n", encoding="utf-8"
    )
    with pytest.raises(PolicyViolation, match="verifyDepsBeforeRun"):
        run_unit(ctx)
    assert not log.exists()


# ------------------------------------------------- corepack and the command policy (open)

OWNER_DECISION = (
    "open finding (session 5, item 1): a launcher that fetches and runs a package manager "
    "passes the command policy; the deny-list change needs the owner (rule 6)"
)


@pytest.mark.xfail(strict=True, reason=OWNER_DECISION)
@pytest.mark.parametrize(
    ("prefix", "argv", "stage"),
    [
        (["corepack", "pnpm@10.0.0"], ["corepack", "pnpm@10.0.0", "test"], "gate"),
        (["corepack", "install"], ["corepack", "install"], "gate"),
        (["corepack", "pnpm"], ["corepack", "pnpm", "dlx", "cowsay"], "prepare"),
        (["corepack", "yarn"], ["corepack", "yarn", "dlx", "cowsay"], "prepare"),
        (["node", PNPM_CJS], ["node", PNPM_CJS, "dlx", "cowsay"], "gate"),
        (["node", PNPM_CJS], ["node", PNPM_CJS, "dlx", "cowsay"], "prepare"),
    ],
    ids=[
        "corepack-pnpm-version", "corepack-install", "corepack-pnpm-dlx-prepare",
        "corepack-yarn-dlx-prepare", "node-pnpm-dlx-gate", "node-pnpm-dlx-prepare",
    ],
)  # fmt: skip
def test_a_launcher_that_fetches_and_runs_code_is_refused(
    prefix: list[str], argv: list[str], stage: str
) -> None:
    """Checked by hand on corepack 0.32.0 with `COREPACK_ENABLE_NETWORK=0`: `corepack
    pnpm@10.0.0 test` and an uncached `packageManager` both tried to download pnpm from the
    npm registry. `pnpm dlx` is refused only when `argv[0]` is pnpm (`FETCH_AND_RUN`)."""
    policy = CommandPolicy(allowed_prefixes=(tuple(prefix),))
    with pytest.raises(PolicyViolation):
        check_argv(argv, policy, stage="gate" if stage == "gate" else "prepare")


@pytest.mark.xfail(strict=True, reason=OWNER_DECISION)
def test_corepack_alone_is_not_an_allowed_prefix() -> None:
    """`[corepack]` allows `corepack install`, `corepack use` and any package manager version,
    as `[uv]` would allow everything; `_NEEDS_PROGRAM` refuses the latter."""
    with pytest.raises(PolicyViolation):
        CommandPolicy(allowed_prefixes=(("corepack",),))
