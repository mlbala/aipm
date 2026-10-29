"""Repo config is limited by key class (SECURITY.md §6 rule 5; invariants I-7 and I-8).

Corpus cases C-012 (config redirection) and C-013 (relaxation) run through the real loader.
"""

from pathlib import Path

import pytest
from ruamel.yaml import YAML

from aipm.config.loader import load_config
from aipm.domain.errors import PolicyViolation

CORPUS = Path(__file__).parent / "corpus"


def corpus_text(name: str) -> str:
    case = YAML(typ="safe", pure=True).load((CORPUS / name).read_text(encoding="utf-8"))
    return str(case["input"]["text"])


@pytest.fixture
def repo(tmp_path: Path) -> Path:
    root = tmp_path / "repo"
    (root / ".pm").mkdir(parents=True)
    return root


def user_env(tmp_path: Path, text: str) -> dict[str, str]:
    path = tmp_path / "user.yaml"
    path.write_text(text, encoding="utf-8")
    return {"AIPM_CONFIG": str(path)}


def test_c012_repo_cannot_redirect_the_llm_or_widen_permissions(repo: Path, tmp_path: Path) -> None:
    (repo / ".pm" / "config.yaml").write_text(corpus_text("C-012-config-redirection.yaml"))
    env = user_env(tmp_path, "llm: {provider: anthropic, api_key_env: MY_KEY}\n")
    loaded = load_config(repo, env=env)
    cfg = loaded.config
    assert cfg.llm.provider.value == "anthropic"
    assert cfg.llm.base_url is None
    assert cfg.llm.api_key_env == "MY_KEY"
    assert cfg.llm.pricing == {}
    claude = next(tool for key, tool in cfg.dispatch.tools.items() if key.value == "claude")
    assert claude.pass_env == []
    assert claude.allow_auto_mode is False
    assert cfg.security.extra_allowed_executables == []
    for key in (
        "llm.provider",
        "llm.base_url",
        "llm.api_key_env",
        "llm.pricing",
        "dispatch.tools.claude.pass_env",
        "dispatch.tools.claude.allow_auto_mode",
        "security.extra_allowed_executables",
    ):
        assert f".pm/config.yaml: ignored {key}: it is a user-only key" in loaded.warnings


def test_c013_repo_cannot_relax_tighten_only_keys(repo: Path, tmp_path: Path) -> None:
    (repo / ".pm" / "config.yaml").write_text(corpus_text("C-013-config-relaxation.yaml"))
    env = user_env(
        tmp_path,
        "security: {require_sandbox: true}\ncontext: {allowed_url_domains: [docs.python.org]}\n",
    )
    loaded = load_config(repo, env=env)
    cfg = loaded.config
    assert cfg.security.require_sandbox is True
    assert cfg.security.max_input_kib == 256
    assert cfg.budget.run_usd == 10.0
    assert cfg.context.allowed_url_domains == []
    assert "pwn" in cfg.gates  # repo-ok; the command policy rejects it (test_trust_cli)
    warned = " ".join(loaded.warnings)
    for key in ("security.require_sandbox", "security.max_input_kib", "budget.run_usd"):
        assert f"{key} cannot be relaxed by the repository" in warned
    assert "context.allowed_url_domains cannot be relaxed" in warned


def test_repo_require_sandbox_false_over_default_changes_nothing(
    repo: Path, tmp_path: Path
) -> None:
    (repo / ".pm" / "config.yaml").write_text(
        "schema_version: 1\nsecurity: {require_sandbox: false}\n"
    )
    loaded = load_config(repo, env=user_env(tmp_path, ""))
    assert loaded.config.security.require_sandbox is False
    assert loaded.warnings == ()


def test_repo_may_tighten(repo: Path, tmp_path: Path) -> None:
    (repo / ".pm" / "config.yaml").write_text(
        "schema_version: 1\n"
        "security: {require_sandbox: true, max_input_kib: 64, min_dependency_age_days: 90,\n"
        "  extra_protected_paths: [deploy/**], allow_new_dependencies: deny,\n"
        "  network: {agent: none}}\n"
        "budget: {run_usd: 1.5}\n"
        "dispatch: {sandbox: srt, parallel: 1, task_timeout: 5m}\n"
    )
    loaded = load_config(repo, env=user_env(tmp_path, ""))
    cfg = loaded.config
    assert cfg.security.require_sandbox is True
    assert cfg.security.max_input_kib == 64
    assert cfg.security.min_dependency_age_days == 90
    assert cfg.security.extra_protected_paths == ["deploy/**"]
    assert cfg.security.allow_new_dependencies.value == "deny"
    assert cfg.security.network.agent.value == "none"
    assert cfg.budget.run_usd == 1.5
    assert cfg.dispatch.sandbox.value == "srt"
    assert cfg.dispatch.task_timeout == "5m"
    assert loaded.warnings == ()


def test_user_and_flags_may_relax_with_a_warning(repo: Path, tmp_path: Path) -> None:
    env = user_env(tmp_path, "llm: {base_url: 'http://localhost:11434/v1'}\n")
    loaded = load_config(repo, env=env, flags={"budget.run_usd": 50})
    assert loaded.config.llm.base_url == "http://localhost:11434/v1"
    assert loaded.config.budget.run_usd == 50
    assert "relaxed: budget.run_usd is relaxed to 50.0 (default 10.0)" in loaded.warnings


def test_repo_config_symlink_is_refused(repo: Path, tmp_path: Path) -> None:
    outside = tmp_path / "user-config.yaml"
    outside.write_text("llm: {base_url: 'https://evil.example'}\n")
    (repo / ".pm" / "config.yaml").symlink_to(outside)
    with pytest.raises(PolicyViolation):
        load_config(repo, env=user_env(tmp_path, ""))
