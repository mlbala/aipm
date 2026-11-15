"""The owner's decisions on the v0.4 review's open items (docs/security/reviews/v0.4.md §6.3;
docs/security/reviews/v0.4-decisions-progress.md).

One section per decision. Every test in a section failed before its change.
"""

from collections.abc import Iterator
from pathlib import Path

import pytest
from typer.testing import CliRunner

from aipm.adapters import claude_code, codex, copilot, gemini
from aipm.cli.main import app
from aipm.config import locations
from aipm.config.loader import load_config, user_redact_patterns
from aipm.config.schema import Config
from aipm.config.stacks import load_stack
from aipm.domain.errors import PolicyViolation
from aipm.observability import tracing
from aipm.security.command_policy import CommandPolicy, Stage, check_argv, compile_prepare
from aipm.security.env_policy import DENIED_NAMES, denied_pass_env

runner = CliRunner()


@pytest.fixture
def isolated(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Iterator[Path]:
    """Per-test home, XDG directories and working directory, outside every repository."""
    home = tmp_path / "user-home"
    home.mkdir()
    monkeypatch.setenv("HOME", str(home))
    for name in ("XDG_CONFIG_HOME", "XDG_STATE_HOME", "XDG_CACHE_HOME", "XDG_DATA_HOME"):
        monkeypatch.setenv(name, str(tmp_path / name.lower()))
    for name in ("AIPM_CONFIG", "AIPM_NON_INTERACTIVE", "AIPM_LOG_LEVEL"):
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setattr(locations, "account_home", lambda: str(home))
    outside = tmp_path / "outside"
    outside.mkdir()
    monkeypatch.chdir(outside)
    yield home


# ---------------------------------------------------------------- v0.1 O-4: init and the repo root


def test_init_refuses_a_user_config_inside_the_target_repo_before_writing(
    isolated: Path, tmp_repo: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """`aipm -C <repo> init` run from another directory checks the user config against <repo>,
    not against the repository around the working directory (there is none here)."""
    del isolated
    inside = tmp_repo / "user-config.yaml"
    inside.write_text("{}\n", encoding="utf-8")
    monkeypatch.setenv("AIPM_CONFIG", str(inside))
    result = runner.invoke(app, ["-C", str(tmp_repo), "init"])
    assert result.exit_code == 6, result.output
    assert "inside the repository" in result.stderr
    assert not (tmp_repo / ".pm").exists()


def test_init_force_still_repairs_a_broken_repo_config(isolated: Path, tmp_repo: Path) -> None:
    """Checking the user config against the root must not read the `.pm/config.yaml` that
    `init --force` is about to rewrite."""
    del isolated
    (tmp_repo / ".pm").mkdir()
    (tmp_repo / ".pm" / "config.yaml").write_text("bogus: [\n", encoding="utf-8")
    result = runner.invoke(app, ["-C", str(tmp_repo), "init", "--force"])
    assert result.exit_code == 0, result.output
    assert "bogus" not in (tmp_repo / ".pm" / "config.yaml").read_text(encoding="utf-8")


# ---------------------------------------------------------------- v0.1 O-2: a missing AIPM_CONFIG


def test_aipm_config_naming_a_missing_file_exits_6(isolated: Path, tmp_path: Path) -> None:
    del isolated
    missing = tmp_path / "nowhere" / "config.yaml"
    with pytest.raises(PolicyViolation, match="does not exist"):
        load_config(None, env={"AIPM_CONFIG": str(missing)})
    with pytest.raises(PolicyViolation, match="does not exist"):
        user_redact_patterns(None, env={"AIPM_CONFIG": str(missing)})


def test_aipm_config_naming_a_dangling_link_exits_6(isolated: Path, tmp_path: Path) -> None:
    del isolated
    link = tmp_path / "config.yaml"
    link.symlink_to(tmp_path / "gone.yaml")
    with pytest.raises(PolicyViolation, match="does not exist"):
        load_config(None, env={"AIPM_CONFIG": str(link)})


def test_the_cli_exits_6_for_a_missing_aipm_config(
    isolated: Path, tmp_repo: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    del isolated
    monkeypatch.setenv("AIPM_CONFIG", str(tmp_path / "missing.yaml"))
    result = runner.invoke(app, ["-C", str(tmp_repo), "init"])
    assert result.exit_code == 6, result.output
    assert "AIPM_CONFIG" in result.stderr
    assert not (tmp_repo / ".pm").exists()


def test_a_missing_default_user_config_is_still_fine(isolated: Path) -> None:
    """A new user has no config file; only an explicit `AIPM_CONFIG` must exist."""
    del isolated
    assert load_config(None, env={}).config == Config()
    assert load_config(None, env={"AIPM_CONFIG": ""}).config == Config()


# ---------------------------------------------------------------- v0.1 O-1 (B): moved directories


def _env(home: Path, **extra: str) -> dict[str, str]:
    return {"HOME": str(home), **extra}


def test_no_location_warning_for_the_account_home(isolated: Path) -> None:
    assert locations.location_warnings(_env(isolated)) == []


def test_aipm_config_is_warned_on_every_run(isolated: Path, tmp_path: Path) -> None:
    user = tmp_path / "user.yaml"
    (found,) = locations.location_warnings(_env(isolated, AIPM_CONFIG=str(user)))
    assert "AIPM_CONFIG" in found
    assert str(user) in found


def test_a_home_other_than_the_account_home_is_warned(isolated: Path, tmp_path: Path) -> None:
    other = tmp_path / "other-home"
    other.mkdir()
    (found,) = locations.location_warnings(_env(other))
    assert "HOME" in found
    assert str(other) in found
    assert str(isolated) in found


def test_the_same_home_through_a_link_is_not_warned(isolated: Path, tmp_path: Path) -> None:
    link = tmp_path / "home-link"
    link.symlink_to(isolated)
    assert locations.location_warnings(_env(link)) == []


def test_an_unknown_account_home_is_warned(isolated: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(locations, "account_home", lambda: None)
    (found,) = locations.location_warnings(_env(isolated))
    assert "cannot look up" in found


@pytest.mark.parametrize(
    "name", ["AIPM_CONFIG", "XDG_CONFIG_HOME", "XDG_STATE_HOME", "XDG_CACHE_HOME"]
)
def test_a_directory_inside_a_git_work_tree_is_warned(
    isolated: Path, tmp_repo: Path, name: str
) -> None:
    target = tmp_repo / "sub" / ("config.yaml" if name == "AIPM_CONFIG" else "dir")
    found = locations.location_warnings(_env(isolated, **{name: str(target)}))
    assert any(name in w and "git work tree" in w and str(tmp_repo) in w for w in found), found


def test_xdg_data_home_and_directories_outside_work_trees_are_not_warned(
    isolated: Path, tmp_repo: Path, tmp_path: Path
) -> None:
    env = _env(
        isolated,
        XDG_DATA_HOME=str(tmp_repo / "data"),
        XDG_CONFIG_HOME=str(tmp_path / "xdg_config_home"),
        XDG_STATE_HOME="",
    )
    assert locations.location_warnings(env) == []


def test_the_cli_prints_location_warnings_on_stderr(
    isolated: Path, tmp_repo: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    del isolated
    monkeypatch.setenv("XDG_STATE_HOME", str(tmp_repo / "state"))
    result = runner.invoke(app, ["--json", "-C", str(tmp_path / "outside"), "doctor"])
    assert "warning: XDG_STATE_HOME" in result.stderr
    assert "XDG_STATE_HOME" not in result.stdout


# ---------------------------------------------------------------- N-2: the pass_env deny list

# Every name and family the owner listed. Families are tested with the members the owner named
# and with others; each entry is refused from every tool's pass_env.
DENIED = [
    # the review's list
    "NODE_OPTIONS", "NODE_PATH", "PYTHONPATH", "PYTHONSTARTUP", "PYTHONHOME", "BASH_ENV", "ENV",
    "COPILOT_ALLOW_ALL",
    "DYLD_INSERT_LIBRARIES", "DYLD_LIBRARY_PATH", "DYLD_FRAMEWORK_PATH",
    "LD_PRELOAD", "LD_LIBRARY_PATH", "LD_AUDIT",
    # the variables aipm sets for agents
    "CLAUDE_CONFIG_DIR", "CODEX_HOME", "COPILOT_HOME", "GEMINI_CLI_HOME", "GEMINI_SANDBOX",
    "DISABLE_AUTOUPDATER", "CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC",
    # the owner's additions
    "PATH", "HOME", "TMPDIR",
    "PERL5OPT", "PERL5LIB", "RUBYOPT", "RUBYLIB",
    "JAVA_TOOL_OPTIONS", "_JAVA_OPTIONS", "JDK_JAVA_OPTIONS",
    "GIT_CONFIG_COUNT", "GIT_CONFIG_KEY_0", "GIT_CONFIG_VALUE_0", "GIT_CONFIG_GLOBAL",
    "GIT_SSH_COMMAND", "GIT_EXEC_PATH", "GIT_DIR", "GIT_WORK_TREE", "GIT_ASKPASS",
    "GOFLAGS", "GOPROXY", "GONOSUMDB", "GONOSUMCHECK", "GOINSECURE", "GOTOOLCHAIN",
    "RUSTFLAGS", "RUSTC_WRAPPER",
    "CARGO_HOME", "CARGO_BUILD_RUSTC_WRAPPER", "CARGO_TARGET_X86_64_UNKNOWN_LINUX_GNU_RUNNER",
    "NPM_CONFIG_REGISTRY", "npm_config_registry", "Npm_Config_Userconfig",
    "npm_CONFIG_globalconfig",
    "PIP_INDEX_URL", "PIP_EXTRA_INDEX_URL", "PIP_CONFIG_FILE",
    "UV_INDEX_URL", "UV_PYTHON", "UV_CONFIG_FILE",
    "SHELLOPTS", "BASHOPTS", "IFS", "PS4", "PROMPT_COMMAND", "ZDOTDIR",
]  # fmt: skip

# Session 2: the names the security review found in the owner's classes (open item 1), one case
# per entry; families with the members the review named.
DENIED_V2 = [
    # Go
    "GOENV", "GOSUMDB", "GOPRIVATE", "GONOPROXY", "GOWORK", "GOROOT", "GOMODCACHE", "CC", "CXX",
    "CGO_CFLAGS", "CGO_LDFLAGS", "CGO_ENABLED",
    # Rust
    "RUSTC", "RUSTC_WORKSPACE_WRAPPER", "RUSTDOC", "RUSTDOCFLAGS",
    "RUSTUP_TOOLCHAIN", "RUSTUP_HOME",
    # Perl and Python
    "PERLLIB", "PERL5DB", "PYTHONUSERBASE",
    # git
    "XDG_CONFIG_HOME",
    # the agents
    "SHELL", "CLAUDE_CODE_SHELL_PREFIX", "CLAUDE_ENV_FILE",
    "GEMINI_CLI_SYSTEM_SETTINGS_PATH", "GEMINI_CLI_SYSTEM_DEFAULTS_PATH",
    "YARN_YARN_PATH", "YARN_RC_FILENAME", "yarn_npm_registry_server", "Yarn_Npm_Auth_Token",
]  # fmt: skip

ALLOWED = ["GITHUB_TOKEN", "MY_API_TOKEN", "LANG", "UVICORN_PORT", "NODE_ENV", "GOPATH_X", "path",
           "CCACHE_DIR", "SHELLCHECK_OPTS", "RUSTY_TOKEN", "YARNISH"]  # fmt: skip


def _user_config(tmp_path: Path, tool: str, names: list[str]) -> dict[str, str]:
    user = tmp_path / "user.yaml"
    listed = ", ".join(f'"{name}"' for name in names)
    text = f"dispatch: {{tools: {{{tool}: {{pass_env: [{listed}]}}}}}}\n"
    user.write_text(text, encoding="utf-8")
    return {"AIPM_CONFIG": str(user), "HOME": str(tmp_path)}


@pytest.mark.parametrize("name", DENIED)
def test_a_denied_name_in_pass_env_exits_6(isolated: Path, tmp_path: Path, name: str) -> None:
    del isolated
    assert denied_pass_env(name)
    with pytest.raises(PolicyViolation, match="pass_env") as info:
        load_config(None, env=_user_config(tmp_path, "claude", ["MY_TOKEN", name]))
    assert name in info.value.message


@pytest.mark.parametrize("name", DENIED_V2)
def test_a_name_the_review_found_in_pass_env_exits_6(
    isolated: Path, tmp_path: Path, name: str
) -> None:
    del isolated
    assert denied_pass_env(name)
    with pytest.raises(PolicyViolation, match="pass_env") as info:
        load_config(None, env=_user_config(tmp_path, "claude", ["MY_TOKEN", name]))
    assert name in info.value.message


@pytest.mark.parametrize("tool", ["claude", "codex", "copilot", "gemini"])
def test_the_deny_list_covers_every_tool(isolated: Path, tmp_path: Path, tool: str) -> None:
    del isolated
    with pytest.raises(PolicyViolation, match=f"dispatch.tools.{tool}.pass_env"):
        load_config(None, env=_user_config(tmp_path, tool, ["LD_PRELOAD"]))


def test_a_command_line_flag_cannot_pass_a_denied_name(isolated: Path, tmp_path: Path) -> None:
    del isolated
    env = {"AIPM_CONFIG": str(tmp_path / "user.yaml"), "HOME": str(tmp_path)}
    (tmp_path / "user.yaml").write_text("", encoding="utf-8")
    with pytest.raises(PolicyViolation, match="pass_env"):
        load_config(None, env=env, flags={"dispatch.tools.claude.pass_env": ["NODE_OPTIONS"]})


@pytest.mark.parametrize("name", ALLOWED)
def test_other_names_still_pass(isolated: Path, tmp_path: Path, name: str) -> None:
    del isolated
    assert not denied_pass_env(name)
    loaded = load_config(None, env=_user_config(tmp_path, "claude", [name]))
    assert loaded.config.dispatch.tools["claude"].pass_env == [name]


def test_every_variable_aipm_sets_for_an_agent_is_denied() -> None:
    """A new adapter's config home or agent setting must join the deny list."""
    homes = {m.CONFIG_HOME.env_var for m in (claude_code, codex, copilot, gemini)}
    agent = {*claude_code.AGENT_ENV, *dict(gemini.GeminiAdapter.agent_env)}
    assert homes | agent <= DENIED_NAMES


# ---------------------------------------------------------------- N-5: the trace endpoint's host


@pytest.mark.parametrize(
    ("environ", "host"),
    [
        ({tracing.ENDPOINT_ENV: "https://collector.example:4318"}, "collector.example:4318"),
        ({tracing.ENDPOINT_ENV: "http://127.0.0.1:4318/"}, "127.0.0.1:4318"),
        ({tracing.ENDPOINT_ENV: "https://user:pw@collector.example/x"}, "collector.example"),
        (
            {
                tracing.ENDPOINT_ENV: "https://collector.example",
                tracing.TRACES_ENDPOINT_ENV: "https://other.example/v1/traces",
            },
            "other.example",
        ),
        ({tracing.ENDPOINT_ENV: "not a url"}, "(no host)"),
        ({tracing.ENDPOINT_ENV: "http://[::1"}, "(no host)"),
        ({tracing.ENDPOINT_ENV: "https://collector.example:99999"}, "(no host)"),
        # urllib3, which sends the spans, ends the host at a backslash; Python's urlsplit does
        # not, so such an endpoint has no one host to print (security review of N-5).
        ({tracing.ENDPOINT_ENV: "http://evil.example\\@localhost:4318"}, "(no host)"),
        ({tracing.ENDPOINT_ENV: "http://a@evil.example@localhost:4318"}, "(no host)"),
        ({tracing.ENDPOINT_ENV: "http://collector.example :4318"}, "(no host)"),
        ({tracing.ENDPOINT_ENV: "http://coll\u0435ctor.example:4318"}, "(no host)"),  # a Cyrillic e
        ({tracing.ENDPOINT_ENV: "ftp://collector.example"}, "(no host)"),
        ({tracing.ENDPOINT_ENV: "http://[::1]:4318"}, "[::1]:4318"),
        ({tracing.ENDPOINT_ENV: "HTTPS://Collector.Example"}, "(no host)"),
    ],
)
def test_the_trace_endpoint_host_is_what_the_exporter_uses(
    environ: dict[str, str], host: str
) -> None:
    assert tracing.endpoint_host(tracing.traces_endpoint(environ)) == host


def test_the_traces_endpoint_follows_the_otlp_rules() -> None:
    assert tracing.traces_endpoint({tracing.ENDPOINT_ENV: "https://c.example"}) == (
        "https://c.example/v1/traces"
    )
    assert tracing.traces_endpoint({tracing.ENDPOINT_ENV: "https://c.example/"}) == (
        "https://c.example/v1/traces"
    )
    traces = {tracing.ENDPOINT_ENV: "https://c.example", tracing.TRACES_ENDPOINT_ENV: "https://t"}
    assert tracing.traces_endpoint(traces) == "https://t"


@pytest.fixture
def no_export(monkeypatch: pytest.MonkeyPatch) -> None:
    """The real OTLP exporter, with sending replaced: tests never open a socket."""
    from opentelemetry.exporter.otlp.proto.http.trace_exporter import (  # noqa: PLC0415
        OTLPSpanExporter,
    )
    from opentelemetry.sdk.trace.export import SpanExportResult  # noqa: PLC0415

    monkeypatch.setattr(OTLPSpanExporter, "export", lambda *_: SpanExportResult.SUCCESS)


@pytest.mark.usefixtures("no_export")
def test_every_trace_run_names_the_host_the_spans_go_to() -> None:
    environ = {tracing.ENDPOINT_ENV: "https://user:pw@collector.example:4318"}
    try:
        assert tracing.configure_tracing(enabled=True, environ=environ) is None
        assert tracing.destination() == "collector.example:4318"
        # The SDK's exporter sends to the URL whose host was printed.
        processor = tracing._state["provider"]._active_span_processor._span_processors[0]  # pyright: ignore[reportPrivateUsage]
        assert processor._batch_processor._exporter._endpoint == (
            "https://user:pw@collector.example:4318/v1/traces"
        )
    finally:
        tracing.shutdown()
    assert tracing.destination() is None


@pytest.mark.usefixtures("no_export")
def test_the_cli_prints_the_trace_host_on_stderr(
    isolated: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    del isolated
    monkeypatch.setenv(tracing.ENDPOINT_ENV, "https://user:pw@collector.example:4318")
    try:
        result = runner.invoke(app, ["--trace", "-C", str(tmp_path / "outside"), "doctor"])
    finally:
        tracing.shutdown()
    assert "warning: --trace sends spans" in result.stderr
    assert "collector.example:4318" in result.stderr
    assert "pw" not in result.stderr


# ---------------------------------------------------------------- N-6: go -modfile and -overlay

GO_POLICY = CommandPolicy(
    allowed_prefixes=(("go", "mod", "download"), ("go", "vet"), ("go", "test"), ("gotestsum",))
)


@pytest.mark.parametrize("stage", ["gate", "prepare"])
@pytest.mark.parametrize(
    "argv",
    [
        ["go", "vet", "-modfile=other.mod", "./..."],
        ["go", "vet", "-modfile", "other.mod", "./..."],
        ["go", "vet", "--modfile=other.mod", "./..."],
        ["go", "vet", "--modfile", "other.mod", "./..."],
        ["go", "test", "-overlay=overlay.json", "./..."],
        ["go", "test", "-overlay", "overlay.json", "./..."],
        ["go", "test", "--overlay=overlay.json", "./..."],
        ["go", "mod", "download", "-modfile=other.mod"],
        ["gotestsum", "--junitfile", "r.xml", "--", "-modfile=other.mod", "./..."],
        ["gotestsum", "--junitfile", "r.xml", "--", "-overlay", "o.json", "./..."],
        ["gotestsum", "--junitfile", "r.xml", "--", "--overlay=o.json", "./..."],
    ],
)
def test_go_modfile_and_overlay_are_refused(argv: list[str], stage: Stage) -> None:
    with pytest.raises(PolicyViolation, match=r"-modfile|-overlay"):
        check_argv(argv, GO_POLICY, stage=stage)


@pytest.mark.parametrize(
    ("argv", "stage"),
    [
        (["go", "vet", "-mod=readonly", "./..."], "gate"),
        (["go", "mod", "download"], "prepare"),
        (["gotestsum", "--junitfile", "r.xml", "--", "-mod=readonly", "./..."], "gate"),
    ],
)
def test_the_go_template_argv_still_passes(argv: list[str], stage: Stage) -> None:
    assert list(check_argv(argv, GO_POLICY, stage=stage)) == argv


# ---------------------------------------------------------------- v0.2 O-1: --ignore-pnpmfile

PNPM_PREPARE = ["pnpm", "install", "--frozen-lockfile", "--ignore-scripts", "--ignore-pnpmfile"]


def test_node_pnpm_prepare_ignores_the_repository_pnpmfile() -> None:
    """A `.pnpmfile.cjs` the repository already had would run in prepare (R-13)."""
    stack = load_stack("node-pnpm")
    assert stack.prepare is not None
    assert list(stack.prepare.run) == PNPM_PREPARE
    policy = Config.model_validate(stack.model_dump(mode="json")).command_policy()
    assert list(compile_prepare(stack.prepare, policy=policy)) == PNPM_PREPARE


def test_node_pnpm_policy_refuses_prepare_without_the_flag() -> None:
    stack = load_stack("node-pnpm")
    policy = Config.model_validate(stack.model_dump(mode="json")).command_policy()
    with pytest.raises(PolicyViolation, match="allowed prefix"):
        check_argv(PNPM_PREPARE[:-1], policy, stage="prepare")


# ---------------------------------------------------------------- the security review's findings


def test_an_ambiguous_trace_endpoint_sends_nothing() -> None:
    environ = {tracing.ENDPOINT_ENV: "http://evil.example\\@localhost:4318"}
    warning = tracing.configure_tracing(enabled=True, environ=environ)
    assert warning is not None and "no spans are sent" in warning
    assert not tracing.enabled()
    assert tracing.destination() is None


@pytest.mark.usefixtures("no_export")
@pytest.mark.parametrize(
    ("proxy", "shown"),
    [
        ({"HTTPS_PROXY": "http://proxy.example:8080"}, "proxy.example:8080 (HTTPS_PROXY)"),
        ({"https_proxy": "proxy.example:3128"}, "proxy.example:3128 (https_proxy)"),
        ({"ALL_PROXY": "http://all.example:1080"}, "all.example:1080 (ALL_PROXY)"),
        # requests takes any *_proxy name in any case, keyed by scheme or scheme://host.
        ({"Https_Proxy": "http://evil.example:8080"}, "evil.example:8080 (Https_Proxy)"),
        (
            {"https://collector.example_proxy": "http://evil.example:8080"},
            "evil.example:8080 (https://collector.example_proxy)",
        ),
    ],
)
def test_the_trace_warning_names_a_proxy_from_the_environment(
    proxy: dict[str, str], shown: str
) -> None:
    environ = {tracing.ENDPOINT_ENV: "https://collector.example", **proxy}
    try:
        assert tracing.configure_tracing(enabled=True, environ=environ) is None
        assert tracing.destination() == f"collector.example, through a proxy: {shown}"
    finally:
        tracing.shutdown()


def test_an_unexpandable_variable_does_not_crash_the_run(isolated: Path) -> None:
    found = locations.location_warnings(_env(isolated, XDG_CACHE_HOME="~nosuchuser_zz/c"))
    assert found == []


def test_a_long_path_keeps_its_end_and_is_resolved(isolated: Path, tmp_path: Path) -> None:
    target = tmp_path / "evilhome"
    target.mkdir()
    padded = str(isolated) + "/." * 150 + "/../" + "evilhome"
    (found,) = locations.location_warnings(_env(Path(padded)))
    assert str(target) in found


@pytest.mark.usefixtures("no_export")
def test_no_proxy_alone_names_no_proxy() -> None:
    environ = {tracing.ENDPOINT_ENV: "https://collector.example", "NO_PROXY": "*"}
    try:
        assert tracing.configure_tracing(enabled=True, environ=environ) is None
        assert tracing.destination() == "collector.example"
    finally:
        tracing.shutdown()


def test_an_exporter_that_cannot_be_built_sends_nothing(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("OTEL_PYTHON_EXPORTER_OTLP_HTTP_CREDENTIAL_PROVIDER", "nope")
    environ = {tracing.ENDPOINT_ENV: "https://collector.example"}
    warning = tracing.configure_tracing(enabled=True, environ=environ)
    assert warning is not None and "no spans are sent" in warning
    assert not tracing.enabled()


@pytest.mark.parametrize("value", ["~{user}", "~", "relative/home"])
def test_a_home_nothing_expands_is_warned(isolated: Path, value: str) -> None:
    """Child processes get HOME as written; `~user` is not the account home for them."""
    import getpass  # noqa: PLC0415

    home = value.format(user=getpass.getuser())
    (found,) = locations.location_warnings({"HOME": home})
    assert "not your account's home" in found
    assert str(isolated) in found
