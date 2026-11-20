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
PNPX_CJS = "node_modules/pnpm/bin/pnpx.cjs"


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
        ["node", "node_modules/pnpm/", "test"],  # pnpm's package.json "main"
        ["node", "node_modules/pnpm/.", "test"],
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


# ------------------------------------------------- corepack and the command policy


@pytest.mark.parametrize(
    ("prefix", "argv", "stage"),
    [
        (["corepack", "pnpm@10.0.0"], ["corepack", "pnpm@10.0.0", "test"], "gate"),
        (["corepack", "install"], ["corepack", "install"], "gate"),
        (["corepack", "pnpm"], ["corepack", "pnpm", "dlx", "cowsay"], "prepare"),
        (["corepack", "yarn"], ["corepack", "yarn", "dlx", "cowsay"], "prepare"),
        (["node", PNPM_CJS], ["node", PNPM_CJS, "dlx", "cowsay"], "gate"),
        (["node", PNPM_CJS], ["node", PNPM_CJS, "dlx", "cowsay"], "prepare"),
        (["node", "node_modules/pnpm/"], ["node", "node_modules/pnpm/", "dlx", "cowsay"], "gate"),
        (["node", PNPX_CJS], ["node", PNPX_CJS, "cowsay"], "gate"),
        (["node", PNPX_CJS], ["node", PNPX_CJS, "cowsay"], "prepare"),
    ],
    ids=[
        "corepack-pnpm-version", "corepack-install", "corepack-pnpm-dlx-prepare",
        "corepack-yarn-dlx-prepare", "node-pnpm-dlx-gate", "node-pnpm-dlx-prepare",
        "node-pnpm-dir-dlx-gate", "node-pnpx-gate", "node-pnpx-prepare",
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


def test_corepack_alone_is_not_an_allowed_prefix() -> None:
    """`[corepack]` allows `corepack install`, `corepack use` and any package manager version,
    as `[uv]` would allow everything; `_NEEDS_PROGRAM` refuses the latter."""
    with pytest.raises(PolicyViolation):
        CommandPolicy(allowed_prefixes=(("corepack",),))


# ------------------------------------------- the owner's decisions on item 1 (follow-up)


@pytest.mark.parametrize(
    "argv",
    [
        ["corepack", "use", "pnpm@10.0.0"],
        ["corepack", "enable"],
        ["corepack", "up"],
        ["corepack", "prepare", "pnpm@10.0.0", "--activate"],
        ["corepack", "pack"],
        ["corepack", "cache", "clean"],
        ["corepack", "--version"],
        ["corepack", "yarnpkg", "test"],
        ["corepack", "PNPM@latest", "test"],
        ["corepack", "pnpm", "install"],
        ["node", "--no-warnings", PNPM_CJS, "test"],
        ["node", "scripts/run.js", "pnpm", "test"],
        ["/usr/bin/node22", "node_modules/pnpm/.", "dlx", "x"],
        ["bun", PNPM_CJS, "dlx", "x"],
    ],
)
def test_other_launcher_shapes_are_refused_in_a_gate(argv: list[str]) -> None:
    """Only `corepack pnpm|yarn|npm …` and `node <pnpm's script> …`, with nothing before the
    script, are read; any other corepack command installs or changes a package manager. Even
    with the whole argv allowed, it is refused (or the prefix itself is)."""
    with pytest.raises(PolicyViolation):
        check_argv(argv, CommandPolicy(allowed_prefixes=(tuple(argv),)), stage="gate")


@pytest.mark.parametrize(
    "argv",
    [
        ["corepack", "pnpm", "test"],
        ["corepack", "yarn", "test"],
        ["corepack", "npm", "test"],
        ["node", PNPM_CJS, "test"],
        ["node", "node_modules/pnpm/", "run", "lint"],
        ["node", "scripts/check.js"],
    ],
)
def test_a_launcher_running_the_tests_still_passes(argv: list[str]) -> None:
    policy = CommandPolicy(allowed_prefixes=(tuple(argv),))
    assert check_argv(argv, policy, stage="gate") == tuple(argv)


@pytest.mark.parametrize(
    "run",
    [
        ["corepack", "pnpm", "install", "--frozen-lockfile"],
        ["node", PNPM_CJS, "install", "--frozen-lockfile"],
        ["node", "node_modules/pnpm/", "install"],
        ["nice", "pnpm", "install", "--frozen-lockfile"],
    ],
    ids=["corepack", "node-script", "node-package", "wrapper"],
)
def test_a_prepare_that_starts_pnpm_through_a_launcher_is_refused(
    tmp_path: Path, run: list[str]
) -> None:
    """The owner's decision: pnpm's store and copy flags go right after `pnpm`, and the
    environment does not beat a committed `pnpm-workspace.yaml` or `.npmrc` (checked by hand on
    pnpm 10.34.9 for both the `npm_config_` and `pnpm_config_` spellings), so a prepare must run
    pnpm itself. It never starts."""
    program, log = recorder(tmp_path, run[0])
    ctx = gate_ctx(tmp_path, [program, "test"], prepare=[program, *run[1:]])
    with pytest.raises(PolicyViolation, match="starts pnpm through") as info:
        run_prepare(ctx)
    assert info.value.exit_code is ExitCode.SECURITY_VIOLATION
    assert "Run pnpm directly" in (info.value.hint or "")
    assert not log.exists()


def test_a_plain_pnpm_prepare_still_runs(tmp_path: Path) -> None:
    program, log = recorder(tmp_path, "pnpm")
    ctx = gate_ctx(tmp_path, [program, "test"], prepare=[program, "install"])
    outcome = run_prepare(ctx)
    assert outcome is not None and outcome.result.status is GateStatus.PASS, outcome
    assert log.exists()


COREPACK_RECORDER = """#!{python}
import os
with open({log!r}, "w") as out:
    out.write(os.environ.get("COREPACK_ENABLE_NETWORK", "unset"))
"""


@pytest.mark.parametrize("name", ["pnpm", "uv", "node"])
def test_gates_tell_corepack_never_to_download(tmp_path: Path, name: str) -> None:
    """`pnpm` on PATH is often corepack's shim, which downloads the version `packageManager`
    names when it is not cached (checked by hand on corepack 0.32.0); a gate never does."""
    log = tmp_path / "corepack.log"
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    program = bin_dir / name
    program.write_text(COREPACK_RECORDER.format(python=sys.executable, log=str(log)))
    program.chmod(0o755)
    ctx = gate_ctx(tmp_path, [str(program), "test"], prepare=[str(program), "install"])
    assert run_unit(ctx) is GateStatus.PASS
    assert log.read_text(encoding="utf-8") == "0"
    outcome = run_prepare(ctx)  # prepare keeps the network its profile allows
    assert outcome is not None and outcome.result.status is GateStatus.PASS, outcome
    assert log.read_text(encoding="utf-8") == "unset"


# ------------------------------------------------------------------ `.npmrc` (R-26)

NPMRC_INSTALLS = {
    "install": "verify-deps-before-run=install\n",
    "spaces-and-quotes": '  verify-deps-before-run = "install"\n',
    "underscores": "verify_deps_before_run=prompt\n",
    "camel-case": "verifyDepsBeforeRun=install\n",
    "upper-case": "VERIFY-DEPS-BEFORE-RUN=install\n",
    "bare-key": "verify-deps-before-run\n",
    "array-key": "verify-deps-before-run[]=install\n",
    "in-a-section": "[x]\nverify-deps-before-run=install\n",
    "expanded-key": "${AIPM_NOPE:-verify-deps-before-run}=install\n",
    "expanded-value": "verify-deps-before-run=${AIPM_NOPE:-install}\n",
}
NPMRC_SAFE = {
    "error": "verify-deps-before-run=error\n",
    "warn": "verify-deps-before-run=warn\n",
    "false": "verify-deps-before-run=false\n",
    "comment": "# verify-deps-before-run=install\n; verify-deps-before-run=install\n",
    "other-keys": "registry=https://registry.npmjs.org/\n//r/:_authToken=${NPM_TOKEN}\n",
    "empty": "",
}


@pytest.mark.parametrize("text", NPMRC_INSTALLS.values(), ids=NPMRC_INSTALLS.keys())
@pytest.mark.parametrize("name", ["npm", "uv", "pnpm"])
def test_every_gate_is_refused_when_npmrc_asks_pnpm_to_install(
    tmp_path: Path, name: str, text: str
) -> None:
    """An npm script can call pnpm, and npm-led gates get only `pnpm_config_…`, which a
    committed `.npmrc` beats (checked by hand on pnpm 10.34.9). The owner's decision: refuse.
    Any gate can reach pnpm through a script, so every gate is refused."""
    program, log = recorder(tmp_path, name)
    ctx = gate_ctx(tmp_path, [program, "test"])
    (ctx.root / ".npmrc").write_text(text, encoding="utf-8")
    with pytest.raises(PolicyViolation, match="verify-deps-before-run") as info:
        run_unit(ctx)
    assert info.value.exit_code is ExitCode.SECURITY_VIOLATION
    assert not log.exists()


@pytest.mark.parametrize("text", NPMRC_SAFE.values(), ids=NPMRC_SAFE.keys())
def test_a_gate_runs_with_a_safe_npmrc(tmp_path: Path, text: str) -> None:
    program, log = recorder(tmp_path, "npm")
    ctx = gate_ctx(tmp_path, [program, "test"])
    (ctx.root / ".npmrc").write_text(text, encoding="utf-8")
    assert run_unit(ctx) is GateStatus.PASS
    assert log.exists()


@pytest.mark.parametrize("kind", ["link", "directory", "not-utf8", "too-big"])
def test_a_gate_is_refused_when_npmrc_cannot_be_checked(tmp_path: Path, kind: str) -> None:
    """pnpm would still read it, so the check fails closed."""
    program, log = recorder(tmp_path, "npm")
    ctx = gate_ctx(tmp_path, [program, "test"])
    target = ctx.root / ".npmrc"
    if kind == "link":
        (tmp_path / "real.npmrc").write_text("verify-deps-before-run=error\n", encoding="utf-8")
        target.symlink_to(tmp_path / "real.npmrc")
    elif kind == "directory":
        target.mkdir()
    elif kind == "not-utf8":
        target.write_bytes(b"verify-deps-before-run=\xff\n")
    else:
        target.write_text("#" * (1_048_576 + 1), encoding="utf-8")
    with pytest.raises(PolicyViolation, match="cannot be checked"):
        run_unit(ctx)
    assert not log.exists()
