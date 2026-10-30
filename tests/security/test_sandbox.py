"""The sandbox: profiles from SECURITY.md §9.1, the argv rules of ADR-0020, failing closed."""

import json
import stat
from pathlib import Path

import pytest

from aipm.config.loader import load_config
from aipm.domain.errors import ExitCode, MissingCapability, PolicyViolation
from aipm.domain.models import Ecosystem
from aipm.execution.process import build_env, run_safe
from aipm.execution.sandbox import (
    AGENT_GLOBAL_CONFIG,
    CREDENTIAL_PATHS,
    ProcessKind,
    ProfilePaths,
    SandboxStatus,
    check_shell_safe,
    launcher_for,
    profile_for,
    resolve_sandbox,
    settings_document,
    wrap,
)
from aipm.security.network import NetworkPolicy, NetworkProfile, allowed_domains, parse_network

STUB_BIN = Path(__file__).resolve().parents[1] / "fakes" / "bin"
NONE = NetworkPolicy(NetworkProfile.NONE)


def _paths(tmp_path: Path, **extra: object) -> ProfilePaths:
    work = tmp_path / "work"
    temp = tmp_path / "temp"
    work.mkdir(exist_ok=True)
    temp.mkdir(exist_ok=True)
    return ProfilePaths(workspace=work, temp_dir=temp, home=tmp_path / "home", **extra)  # type: ignore[arg-type]


def _write_exe(path: Path, body: str) -> Path:
    path.write_text(f"#!/bin/sh\n{body}\n", encoding="utf-8")
    path.chmod(0o755)
    return path


# ---------------------------------------------------------------- network profiles


def test_none_allows_no_domain_at_all() -> None:
    assert allowed_domains(NetworkProfile.NONE) == ()
    assert parse_network("none") == NONE


def test_registries_come_from_the_ecosystems() -> None:
    policy = parse_network("registries", ecosystems=[Ecosystem.PYPI, Ecosystem.NPM])
    assert policy.domains == ("pypi.org", "files.pythonhosted.org", "registry.npmjs.org")
    assert parse_network("registries").domains == ()


def test_api_only_names_its_domains() -> None:
    policy = parse_network("api-only:api.anthropic.com,*.example.org")
    assert policy.profile is NetworkProfile.API_ONLY
    assert policy.domains == ("api.anthropic.com", "*.example.org")


@pytest.mark.parametrize(
    "spec",
    [
        "api-only",
        "api-only:",
        "api-only:localhost",
        "api-only:*",
        "api-only:evil.example/path",
        "api-only:a.example,",
        "api-only:EVIL.example",
        "none:evil.example",
        "open:evil.example",
        "registries:evil.example",
        "everything",
    ],
)
def test_bad_network_specs_are_refused(spec: str) -> None:
    with pytest.raises(PolicyViolation) as info:
        parse_network(spec)
    assert info.value.exit_code is ExitCode.SECURITY_VIOLATION


def test_too_many_api_domains_are_refused() -> None:
    spec = "api-only:" + ",".join(f"d{i}.example" for i in range(33))
    with pytest.raises(PolicyViolation, match="1 to 32"):
        parse_network(spec)


def test_open_names_no_domain_and_srt_refuses_it(tmp_path: Path) -> None:
    policy = parse_network("open")
    assert (policy.profile, policy.domains) == (NetworkProfile.OPEN, ())
    profile = profile_for(ProcessKind.GATE, policy, _paths(tmp_path), runtime="/bin/srt")
    with pytest.raises(MissingCapability, match="srt cannot express") as info:
        settings_document(profile)
    assert info.value.exit_code is ExitCode.MISSING_TOOL


def test_wrap_refuses_open_before_writing_settings(tmp_path: Path) -> None:
    paths = _paths(tmp_path)
    srt = _write_exe(tmp_path / "srt", "exit 0")
    profile = profile_for(ProcessKind.GATE, parse_network("open"), paths, runtime=str(srt))
    with pytest.raises(MissingCapability):
        wrap(["ruff"], profile)
    assert list(paths.temp_dir.iterdir()) == []


# ---------------------------------------------------------------- `open` needs the user config


def _repo(tmp_path: Path, text: str = "schema_version: 1\n") -> Path:
    repo = tmp_path / "repo"
    (repo / ".pm").mkdir(parents=True)
    (repo / ".pm" / "config.yaml").write_text(text, encoding="utf-8")
    return repo


def test_a_repository_cannot_open_the_network(tmp_path: Path) -> None:
    repo = _repo(tmp_path, "schema_version: 1\nsecurity: {network: {gates: open}}\n")
    loaded = load_config(repo, env={"AIPM_CONFIG": str(tmp_path / "none.yaml")})
    assert loaded.config.security.network.gates is NetworkProfile.NONE
    assert any("cannot be relaxed" in w for w in loaded.warnings)


def test_the_environment_cannot_open_the_network(tmp_path: Path) -> None:
    env = {
        "AIPM_CONFIG": str(tmp_path / "none.yaml"),
        "AIPM_SECURITY__NETWORK__GATES": "open",
    }
    with pytest.raises(PolicyViolation, match="does not set it"):
        load_config(_repo(tmp_path), env=env)


def test_the_user_config_can_open_the_network_and_it_is_warned(tmp_path: Path) -> None:
    user = tmp_path / "user.yaml"
    user.write_text("schema_version: 1\nsecurity: {network: {gates: open}}\n", encoding="utf-8")
    loaded = load_config(_repo(tmp_path), env={"AIPM_CONFIG": str(user)})
    assert loaded.config.security.network.gates is NetworkProfile.OPEN
    assert "relaxed: security.network.gates is relaxed to open (default none)" in loaded.warnings


# ---------------------------------------------------------------- profiles (SECURITY.md §9.1)


def test_gate_profile_matches_the_table(tmp_path: Path) -> None:
    paths = _paths(tmp_path, config_home=tmp_path / "agent-home")
    profile = profile_for(ProcessKind.GATE, NONE, paths, runtime="/bin/srt")
    assert profile.allow_write == (paths.workspace, paths.temp_dir)
    assert profile.network.domains == ()
    for rel in CREDENTIAL_PATHS:
        assert paths.home / rel in profile.deny_read
    assert tmp_path / "agent-home" in profile.deny_read
    assert paths.home / ".claude" not in profile.deny_read


def test_gate_profile_hides_the_global_agent_homes_in_manual_mode(tmp_path: Path) -> None:
    paths = _paths(tmp_path)
    profile = profile_for(ProcessKind.GATE, NONE, paths, runtime="/bin/srt")
    for rel in (".claude", ".codex", ".gemini", ".copilot"):
        assert paths.home / rel in profile.deny_read


def test_every_profile_denies_writes_to_protected_paths_and_global_config(tmp_path: Path) -> None:
    paths = _paths(tmp_path)
    for kind in ProcessKind:
        profile = profile_for(kind, NONE, paths, runtime="/bin/srt")
        for rel in (".git", ".pm", "AGENTS.md", ".claude", ".github"):
            assert paths.workspace / rel in profile.deny_write, (kind, rel)
        for rel in AGENT_GLOBAL_CONFIG:
            assert paths.home / rel in profile.deny_write, (kind, rel)


def test_agent_profile_matches_the_table(tmp_path: Path) -> None:
    paths = _paths(
        tmp_path,
        config_home=tmp_path / "cfg",
        main_pm=tmp_path / "main" / ".pm",
        other_worktrees=(tmp_path / "other",),
    )
    profile = profile_for(ProcessKind.AGENT, NONE, paths, runtime="/bin/srt")
    assert tmp_path / "cfg" in profile.allow_write
    assert tmp_path / "main" / ".pm" in profile.deny_read
    assert tmp_path / "other" in profile.deny_read


def test_agent_profile_without_the_optional_paths(tmp_path: Path) -> None:
    paths = _paths(tmp_path)
    profile = profile_for(ProcessKind.AGENT, NONE, paths, runtime="/bin/srt")
    assert profile.allow_write == (paths.workspace, paths.temp_dir)


def test_only_prepare_may_write_package_caches(tmp_path: Path) -> None:
    paths = _paths(tmp_path)
    prepare = profile_for(ProcessKind.PREPARE, NONE, paths, runtime="/bin/srt")
    gate = profile_for(ProcessKind.GATE, NONE, paths, runtime="/bin/srt")
    assert paths.home / ".cache" / "uv" in prepare.allow_write
    assert paths.home / ".cache" / "uv" not in gate.allow_write


def test_scanner_writes_only_its_output_dir(tmp_path: Path) -> None:
    paths = _paths(tmp_path, output_dir=tmp_path / "out")
    profile = profile_for(ProcessKind.SCANNER, NONE, paths, runtime="/bin/srt")
    assert profile.allow_write == (tmp_path / "out",)
    bare = profile_for(ProcessKind.SCANNER, NONE, _paths(tmp_path), runtime="/bin/srt")
    assert bare.allow_write == (tmp_path / "temp",)


def test_settings_document_uses_the_srt_field_names(tmp_path: Path) -> None:
    paths = _paths(tmp_path)
    network = parse_network("api-only:semgrep.dev")
    doc = settings_document(profile_for(ProcessKind.SCANNER, network, paths, runtime="/bin/srt"))
    assert doc["network"] == {
        "allowedDomains": ["semgrep.dev"],
        "deniedDomains": [],
        "strictAllowlist": True,
    }
    filesystem = doc["filesystem"]
    assert isinstance(filesystem, dict)
    assert set(filesystem) == {"denyRead", "allowWrite", "denyWrite"}  # pyright: ignore[reportUnknownArgumentType]


def test_every_path_is_literal_so_srt_never_reads_it_as_a_glob(tmp_path: Path) -> None:
    """On macOS srt reads `[`, `*` and `?` in a path as a pattern unless marked literal."""
    work = tmp_path / "w[1]*"
    work.mkdir()
    temp = tmp_path / "temp"
    temp.mkdir()
    paths = ProfilePaths(workspace=work, temp_dir=temp, home=tmp_path / "home")
    doc = settings_document(profile_for(ProcessKind.GATE, NONE, paths, runtime="/bin/srt"))
    filesystem = doc["filesystem"]
    assert isinstance(filesystem, dict)
    for key in ("denyRead", "allowWrite", "denyWrite"):
        entries = filesystem[key]  # pyright: ignore[reportUnknownVariableType]
        assert isinstance(entries, list)
        for entry in entries:  # pyright: ignore[reportUnknownVariableType]
            assert isinstance(entry, dict)
            assert entry["literal"] is True
    assert {"path": str(work), "literal": True} in filesystem["allowWrite"]


def test_env_files_are_denied_by_pattern_when_the_workspace_has_no_glob_chars(
    tmp_path: Path,
) -> None:
    paths = _paths(tmp_path)
    doc = settings_document(profile_for(ProcessKind.GATE, NONE, paths, runtime="/bin/srt"))
    filesystem = doc["filesystem"]
    assert isinstance(filesystem, dict)
    assert f"{paths.workspace}/**/.env*" in filesystem["denyWrite"]


# ---------------------------------------------------------------- wrap (ADR-0020)


def test_wrap_writes_private_settings_and_keeps_argv_whole(tmp_path: Path) -> None:
    paths = _paths(tmp_path)
    srt = _write_exe(tmp_path / "srt", "exit 0")
    profile = profile_for(ProcessKind.GATE, NONE, paths, runtime=str(srt))
    wrapped = wrap(["ruff", "check", "src/a b.py"], profile)
    assert wrapped[:2] == (str(srt), "--settings")
    assert wrapped[3:] == ("--", "ruff", "check", "src/a b.py")
    settings = Path(wrapped[2])
    assert settings.parent == paths.temp_dir
    assert stat.S_IMODE(settings.stat().st_mode) == 0o600
    assert json.loads(settings.read_text(encoding="utf-8"))["network"]["allowedDomains"] == []


@pytest.mark.parametrize(
    "arg",
    [
        "a'b",
        'a"b',
        "a`id`",
        "$(id)",
        "$HOME",
        "a\\b",
        "a!b",
        "a\nb",
        "a\tb",
        "a\x1bb",
        "",
        "~",
        "~root/x",
        "\u202eabc",
    ],
)
def test_shell_active_elements_are_refused(arg: str) -> None:
    with pytest.raises(PolicyViolation) as info:
        check_shell_safe(["ruff", arg])
    assert info.value.exit_code is ExitCode.SECURITY_VIOLATION


@pytest.mark.parametrize(
    "arg", ["src/a b.py", "--cov-fail-under=80", "a;b", "a|b", "a&b", "x*y", "a~b", "ünï.py"]
)
def test_quotable_elements_are_accepted(arg: str) -> None:
    check_shell_safe(["ruff", arg])


def test_wrap_refuses_before_writing_settings(tmp_path: Path) -> None:
    paths = _paths(tmp_path)
    srt = _write_exe(tmp_path / "srt", "exit 0")
    profile = profile_for(ProcessKind.GATE, NONE, paths, runtime=str(srt))
    with pytest.raises(PolicyViolation):
        wrap(["ruff", "$(id)"], profile)
    assert list(paths.temp_dir.iterdir()) == []


def test_wrap_needs_a_runtime_it_can_run(tmp_path: Path) -> None:
    paths = _paths(tmp_path)
    profile = profile_for(ProcessKind.GATE, NONE, paths, runtime=str(tmp_path / "gone"))
    with pytest.raises(MissingCapability) as info:
        wrap(["ruff"], profile)
    assert info.value.exit_code is ExitCode.MISSING_TOOL


def test_run_safe_runs_the_process_through_the_wrapper(tmp_path: Path) -> None:
    paths = _paths(tmp_path)
    profile = profile_for(ProcessKind.GATE, NONE, paths, runtime=str(STUB_BIN / "srt"))
    result = run_safe(
        ["/bin/echo", "hello world"], cwd=tmp_path, env=build_env(), timeout_s=10, sandbox=profile
    )
    assert result.returncode == 0
    assert result.stdout == b"hello world\n"
    assert result.argv[0] == str(STUB_BIN / "srt")


def test_run_safe_refuses_an_unsafe_argv_under_a_profile(tmp_path: Path) -> None:
    paths = _paths(tmp_path)
    profile = profile_for(ProcessKind.GATE, NONE, paths, runtime=str(STUB_BIN / "srt"))
    with pytest.raises(PolicyViolation):
        run_safe(
            ["/bin/echo", "$(id)"], cwd=tmp_path, env=build_env(), timeout_s=10, sandbox=profile
        )


# ---------------------------------------------------------------- detection


def _resolve(tmp_path: Path, mode: str = "auto", *, require: bool = False) -> SandboxStatus:
    repo = tmp_path / "repo"
    repo.mkdir(exist_ok=True)
    temp = tmp_path / "temp"
    temp.mkdir(exist_ok=True)
    return resolve_sandbox(mode=mode, require=require, repo=repo, temp_dir=temp)


@pytest.fixture
def no_srt(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    empty = tmp_path / "empty-bin"
    empty.mkdir()
    monkeypatch.setenv("PATH", f"{empty}:/usr/bin:/bin")
    # A real srt in /usr/bin would defeat this fixture.
    if any((Path(d) / "srt").exists() for d in ("/usr/bin", "/bin")):
        pytest.skip("srt is installed system-wide")


def test_missing_srt_warns(no_srt: None, tmp_path: Path) -> None:
    status = _resolve(tmp_path)
    assert status.runtime is None
    assert status.warning is not None
    assert "srt is not installed" in status.warning
    assert "npm install -g @anthropic-ai/sandbox-runtime" in status.warning


def test_missing_srt_exits_8_when_required(no_srt: None, tmp_path: Path) -> None:
    with pytest.raises(MissingCapability) as info:
        _resolve(tmp_path, require=True)
    assert info.value.exit_code is ExitCode.MISSING_TOOL


def test_missing_srt_exits_8_when_the_mode_names_it(no_srt: None, tmp_path: Path) -> None:
    with pytest.raises(MissingCapability):
        _resolve(tmp_path, "srt")


def test_mode_none_warns_and_never_looks_for_srt(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("PATH", f"{STUB_BIN}:/usr/bin:/bin")
    status = _resolve(tmp_path, "none")
    assert status.runtime is None
    assert status.warning is not None
    assert "dispatch.sandbox is none" in status.warning


def test_mode_none_loses_to_require_sandbox(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("PATH", f"{STUB_BIN}:/usr/bin:/bin")
    with pytest.raises(MissingCapability, match=r"dispatch\.sandbox is none"):
        _resolve(tmp_path, "none", require=True)


@pytest.mark.parametrize("mode", ["auto", "srt", "tool-native"])
def test_a_working_srt_is_used(mode: str, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("PATH", f"{STUB_BIN}:/usr/bin:/bin")
    status = _resolve(tmp_path, mode)
    assert status.runtime == str(STUB_BIN / "srt")
    assert status.warning is None


def test_an_srt_that_cannot_start_counts_as_missing(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    _write_exe(bin_dir / "srt", "echo 'ripgrep not found' >&2; exit 1")
    monkeypatch.setenv("PATH", f"{bin_dir}:/usr/bin:/bin")
    status = _resolve(tmp_path)
    assert status.runtime is None
    assert status.warning is not None
    assert "ripgrep not found" in status.warning
    with pytest.raises(MissingCapability, match="ripgrep not found"):
        _resolve(tmp_path, require=True)


def test_an_srt_that_fails_silently_reports_its_exit_code(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    _write_exe(bin_dir / "srt", "exit 3")
    monkeypatch.setenv("PATH", f"{bin_dir}:/usr/bin:/bin")
    status = _resolve(tmp_path)
    assert status.warning is not None
    assert "exit 3" in status.warning


def test_an_srt_inside_the_repository_is_refused(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    repo = tmp_path / "repo"
    (repo / "bin").mkdir(parents=True)
    _write_exe(repo / "bin" / "srt", "exit 0")
    monkeypatch.setenv("PATH", f"{repo / 'bin'}:/usr/bin:/bin")
    with pytest.raises(PolicyViolation, match="inside the repository"):
        _resolve(tmp_path)


# ---------------------------------------------------------------- srt's interpreter (review)


def _env_node_srt(where: Path) -> Path:
    """A copy of the stub srt whose first line asks env for node, like the real one."""
    body = (STUB_BIN / "srt").read_text(encoding="utf-8").split("\n", 1)[1]
    return _write_exe_raw(where / "srt", "#!/usr/bin/env node\n" + body)


def _write_exe_raw(path: Path, text: str) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")
    path.chmod(0o755)
    return path


def test_srt_s_interpreter_is_never_taken_from_the_repository(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    repo = tmp_path / "repo"
    marker = tmp_path / "planted-node-ran"
    planted = _write_exe_raw(repo / ".venv" / "bin" / "node",
                             f"#!/bin/sh\necho ran > '{marker}'\nexit 0\n")  # fmt: skip
    good_dir = tmp_path / "tools"
    good = _write_exe_raw(
        good_dir / "node", '#!/bin/sh\nscript="$1"; shift\nexec /bin/sh "$script" "$@"\n'
    )
    srt = _env_node_srt(tmp_path / "srt-bin")
    monkeypatch.setenv("PATH", f"{planted.parent}:{srt.parent}:{good_dir}:/usr/bin:/bin")
    temp = tmp_path / "temp"
    temp.mkdir()
    status = resolve_sandbox(mode="srt", require=True, repo=repo, temp_dir=temp)
    assert status.launcher == (str(good), str(srt))
    assert not marker.exists(), "the node planted in the repository ran"
    profile = profile_for(ProcessKind.GATE, NONE, _paths(tmp_path), runtime=status.launcher)
    assert wrap(["ruff"], profile)[:2] == (str(good), str(srt))


def test_srt_needs_its_interpreter_outside_the_repository(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    repo = tmp_path / "repo"
    planted = _write_exe_raw(repo / ".venv" / "bin" / "node", "#!/bin/sh\nexit 0\n")
    srt = _env_node_srt(tmp_path / "srt-bin")
    monkeypatch.setenv("PATH", f"{planted.parent}:/usr/bin:/bin")
    with pytest.raises(MissingCapability, match="not on PATH outside the repository"):
        launcher_for(str(srt), repo)


@pytest.mark.parametrize("first", ["#!/usr/bin/env -S node --x", "#!/usr/bin/env", "#!"])
def test_a_first_line_aipm_cannot_read_exits_8(tmp_path: Path, first: str) -> None:
    srt = _write_exe_raw(tmp_path / "srt", f"{first}\n")
    with pytest.raises(MissingCapability):
        launcher_for(str(srt), tmp_path / "repo")


def test_an_absolute_interpreter_inside_the_repository_is_refused(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    interp = _write_exe_raw(repo / "bin" / "node", "#!/bin/sh\n")
    srt = _write_exe_raw(tmp_path / "srt", f"#!{interp}\n")
    with pytest.raises(PolicyViolation, match="inside the repository"):
        launcher_for(str(srt), repo)
    native = tmp_path / "srt-native"
    native.write_bytes(b"\x7fELF\x02\x01")
    assert launcher_for(str(native), repo) == (str(native),)
    with pytest.raises(MissingCapability):
        launcher_for(str(tmp_path / "missing"), repo)
