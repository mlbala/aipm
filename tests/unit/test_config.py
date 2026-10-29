"""The configuration schema, layers and stack templates (ARCHITECTURE §13.1, §15)."""

from pathlib import Path
from typing import Any

import pytest

from aipm.config import schema
from aipm.config.loader import defaults, load_config, relaxations, user_config_path
from aipm.config.schema import (
    INTERSECTION,
    MAX,
    MIN,
    MIN_DURATION,
    NETWORK_RANK,
    TRUE_WINS,
    UNION,
    Config,
    KeyClass,
    Tighten,
    key_class,
    stricter,
)
from aipm.config.stacks import available_stacks, load_stack
from aipm.domain.errors import SchemaError, UsageError
from aipm.security.command_policy import compile_gate, compile_prepare
from aipm.security.paths import SafeRelPath
from aipm.state.yamlio import dump_yaml


def write(path: Path, text: str) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")
    return path


@pytest.fixture
def env(tmp_path: Path) -> dict[str, str]:
    """An environment whose user config file does not exist yet."""
    return {"AIPM_CONFIG": str(tmp_path / "user" / "config.yaml")}


# ---------------------------------------------------------------- defaults and schema


def test_defaults_yaml_equals_the_schema_defaults() -> None:
    assert defaults() == Config()


def test_defaults_match_architecture_section_15() -> None:
    cfg = Config()
    assert cfg.llm.provider.value == "anthropic"
    assert cfg.llm.api_key_env == "ANTHROPIC_API_KEY"
    assert cfg.llm.max_output_tokens == 8000
    assert cfg.dispatch.task_timeout == "20m"
    assert cfg.budget.model_dump() == {"run_usd": 10.0, "task_usd": 2.0, "run_tokens": 2_000_000}
    assert cfg.security.network.model_dump(mode="json") == {
        "agent": "api-only",
        "gates": "none",
        "prepare": "registries",
    }
    assert cfg.security.max_input_kib == 256
    assert not any(key in cfg.llm.model_dump() for key in ("temperature", "top_p", "top_k"))


def test_to_document_holds_only_the_keys_that_were_set() -> None:
    assert Config().to_document() == {"schema_version": 1}
    cfg = Config.model_validate({"project": {"name": "demo"}, "logging": {"json": True}})
    assert cfg.to_document() == {
        "schema_version": 1,
        "project": {"name": "demo"},
        "logging": {"json": True},
    }


@pytest.mark.parametrize(
    "data",
    [
        {"llm": {"temperature": 0.2}},
        {"llm": {"models": {"writer": "x"}}},
        {"llm": {"base_url": "file:///etc/passwd"}},
        {"dispatch": {"parallel": 9}},
        {"dispatch": {"task_timeout": "20 minutes"}},
        {"dispatch": {"tools": {"cursor": {}}}},
        {"security": {"extra_redact_patterns": ["("]}},
        {"security": {"extra_redact_patterns": [".*"]}},
        {"security": {"extra_protected_paths": ["../x"]}},
        {"context": {"allowed_url_domains": ["not a domain"]}},
        {"git": {"integration_branch": "a/../b"}},
        {"git": {"integration_branch": "-x"}},
        {"test_roots": ["/abs"]},
        {"gates": {"Bad Name": {"builtin": "osv"}}},
        {"scanners": {"semgrep": {"configs": ["auto"]}}},
        {"telemetry": True},
    ],
)
def test_schema_rejects(data: dict[str, Any], env: dict[str, str]) -> None:
    write(Path(env["AIPM_CONFIG"]), _yaml(data))
    with pytest.raises(SchemaError):
        load_config(None, env=env)


def _yaml(data: dict[str, Any]) -> str:
    return dump_yaml(data)


# ---------------------------------------------------------------- key classes and rules


def test_key_classes_follow_architecture_section_15() -> None:
    user_only = {
        ("LlmConfig", "provider"), ("LlmConfig", "base_url"), ("LlmConfig", "api_key_env"),
        ("LlmConfig", "pricing"), ("ToolConfig", "pass_env"), ("ToolConfig", "allow_auto_mode"),
        ("SecurityConfig", "extra_allowed_executables"),
    }  # fmt: skip
    tighten_sections = {"BudgetConfig", "NetworkConfig"}
    for name in dir(schema):
        model = getattr(schema, name)
        if not (isinstance(model, type) and hasattr(model, "model_fields")):
            continue
        for field_name, field in model.model_fields.items():
            found = key_class(field.metadata)
            if (name, field_name) in user_only:
                assert found is KeyClass.USER_ONLY, (name, field_name)
            elif name in tighten_sections or (name == "SecurityConfig" and field_name != "network"):
                assert isinstance(found, Tighten), (name, field_name)
    for field_name in ("parallel", "max_retries", "task_timeout", "sandbox"):
        assert isinstance(
            key_class(schema.DispatchConfig.model_fields[field_name].metadata), Tighten
        )
    assert isinstance(key_class(schema.ToolConfig.model_fields["bare"].metadata), Tighten)
    assert (
        key_class(schema.ContextConfig.model_fields["allowed_url_domains"].metadata) is INTERSECTION
    )


@pytest.mark.parametrize(
    ("rule", "current", "proposed", "expected"),
    [
        (TRUE_WINS, True, False, True),
        (TRUE_WINS, False, True, True),
        (MIN, 10.0, 1000.0, 10.0),
        (MIN, 10.0, 5.0, 5.0),
        (MAX, 30, 7, 30),
        (MIN_DURATION, "20m", "2h", "20m"),
        (MIN_DURATION, "20m", "90s", "90s"),
        (UNION, ["a"], ["b", "a"], ["a", "b"]),
        (INTERSECTION, ["a", "b"], ["b", "c"], ["b"]),
        (NETWORK_RANK, "none", "registries", "none"),
        (NETWORK_RANK, "registries", "api-only", "api-only"),
    ],
)
def test_stricter(rule: Tighten, current: object, proposed: object, expected: object) -> None:
    assert stricter(rule, current, proposed) == expected


# ---------------------------------------------------------------- layers


def test_layer_order_defaults_user_repo_env_flags(tmp_path: Path, env: dict[str, str]) -> None:
    write(
        Path(env["AIPM_CONFIG"]),
        "llm: {models: {default: user-model}}\nlogging: {level: warning}\n",
    )
    repo = tmp_path / "repo"
    write(repo / ".pm" / "config.yaml", "schema_version: 1\nllm: {models: {default: repo-model}}\n")
    loaded = load_config(repo, env=env)
    assert loaded.config.llm.models == {"default": "repo-model"}
    assert loaded.config.logging.level == "warning"
    assert loaded.sources == (env["AIPM_CONFIG"], ".pm/config.yaml")

    env_more = {**env, "AIPM_LLM__MODELS__DEFAULT": "env-model", "AIPM_LOG_LEVEL": "debug"}
    loaded = load_config(repo, env=env_more)
    assert loaded.config.llm.models == {"default": "env-model"}
    assert loaded.config.logging.level == "debug"

    loaded = load_config(repo, env=env_more, flags={"llm.models": {"default": "flag-model"}})
    assert loaded.config.llm.models == {"default": "flag-model"}


def test_environment_values_are_parsed_as_yaml_scalars(env: dict[str, str]) -> None:
    loaded = load_config(
        None,
        env={
            **env,
            "AIPM_BUDGET__RUN_USD": "5",
            "AIPM_DISPATCH__FAIL_FAST": "false",
            "AIPM_CONTEXT__ALLOWED_URL_DOMAINS": "[docs.python.org]",
            "AIPM_DISPATCH__TASK_TIMEOUT": "5m",
            "AIPM_NO_COLOR": "1",
            "AIPM_EMPTY__VALUE": "",
        },
    )
    assert loaded.config.budget.run_usd == 5.0
    assert loaded.config.dispatch.fail_fast is False
    assert loaded.config.context.allowed_url_domains == ["docs.python.org"]
    with pytest.raises(SchemaError, match=r"llm\.models\.default"):
        load_config(None, env={**env, "AIPM_LLM__MODELS__DEFAULT": "[unclosed"})


def test_unknown_environment_keys_are_errors(env: dict[str, str]) -> None:
    with pytest.raises(SchemaError, match="AIPM_"):
        load_config(None, env={**env, "AIPM_LLM__TEMPERATURE": "0"})
    with pytest.raises(SchemaError, match="conflicts"):
        load_config(None, env={**env, "AIPM_LOG_LEVEL": "debug", "AIPM_LOGGING__LEVEL__X": "1"})


def test_user_config_problems(tmp_path: Path, env: dict[str, str]) -> None:
    path = Path(env["AIPM_CONFIG"])
    write(path, "- not a mapping\n")
    with pytest.raises(SchemaError, match="mapping"):
        load_config(None, env=env)
    path.write_bytes(b"\xff")
    with pytest.raises(SchemaError, match="UTF-8"):
        load_config(None, env=env)
    path.unlink()
    path.mkdir()
    with pytest.raises(SchemaError, match="cannot read"):
        load_config(None, env=env)
    write(tmp_path / "empty.yaml", "")
    assert load_config(None, env={"AIPM_CONFIG": str(tmp_path / "empty.yaml")}).config == Config()


def test_newer_schema_version_in_a_layer(tmp_path: Path, env: dict[str, str]) -> None:
    repo = tmp_path / "repo"
    write(repo / ".pm" / "config.yaml", "schema_version: 2\n")
    with pytest.raises(SchemaError, match="schema_version 2") as info:
        load_config(repo, env=env)
    assert info.value.hint == "Upgrade aipm to read this file."


def test_many_errors_are_summarized(env: dict[str, str]) -> None:
    write(Path(env["AIPM_CONFIG"]), "a: 1\nb: 2\nc: 3\nd: 4\ne: 5\nf: 6\n")
    with pytest.raises(SchemaError, match="and 1 more"):
        load_config(None, env=env)


def test_user_config_path(tmp_path: Path) -> None:
    assert user_config_path({"AIPM_CONFIG": str(tmp_path / "c.yaml")}) == tmp_path / "c.yaml"
    assert user_config_path({}).name == "config.yaml"


def test_user_relaxations_are_reported(env: dict[str, str]) -> None:
    write(
        Path(env["AIPM_CONFIG"]),
        "security: {max_input_kib: 1024, network: {gates: registries}}\n"
        "dispatch: {sandbox: none, tools: {claude: {bare: false}}}\n",
    )
    loaded = load_config(None, env=env)
    found = relaxations(loaded.config)
    assert "security.max_input_kib is relaxed to 1024 (default 256)" in found
    assert "security.network.gates is relaxed to registries (default none)" in found
    assert "dispatch.sandbox is relaxed to none (default auto)" in found
    assert "dispatch.tools.claude.bare is relaxed to False (default True)" in found
    assert all(f"relaxed: {item}" in loaded.warnings for item in found)


# ---------------------------------------------------------------- stack templates


def test_python_uv_is_the_only_v01_stack() -> None:
    assert available_stacks() == ["python-uv"]
    with pytest.raises(UsageError, match="unknown stack"):
        load_stack("node-npm")
    with pytest.raises(UsageError, match="unknown stack"):
        load_stack("../defaults")


def test_python_uv_template_matches_architecture_and_passes_the_policy() -> None:
    stack = load_stack("python-uv")
    assert stack.test_roots == ["tests"]
    assert set(stack.gates) == {
        "lint", "format", "types", "unit", "secrets", "sast", "deps", "ac_trace", "ac_review",
    }  # fmt: skip
    cfg = Config.model_validate(stack.model_dump(mode="json"))
    policy = cfg.command_policy()
    assert stack.prepare is not None
    assert compile_prepare(stack.prepare, policy=policy) == ("uv", "sync", "--frozen")
    paths = [SafeRelPath("src/app.py"), SafeRelPath("tests/test_app.py")]
    for name, gate in stack.gates.items():
        if gate.run is None:
            continue
        argv = compile_gate(gate, paths=paths, policy=policy, report_file=Path("/r/report.xml"))
        assert argv[:4] == ("uv", "run", "--frozen", "--offline"), name
    assert stack.gates["unit"].run is not None
    assert "{report_file}" in stack.gates["unit"].run


def test_command_policy_includes_user_extras() -> None:
    cfg = Config.model_validate(
        {
            "allowed_executables": [["uv", "run", "--frozen", "--offline", "pytest"]],
            "security": {"extra_allowed_executables": [["make", "test"]]},
            "test_roots": ["tests"],
        }
    )
    policy = cfg.command_policy()
    assert ("make", "test") in policy.allowed_prefixes
    assert policy.test_roots == ("tests",)
