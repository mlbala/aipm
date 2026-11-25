"""`aipm setup` end to end with a scripted prompter and a fake keychain (ADR-0033)."""

import stat
from collections.abc import Sequence
from pathlib import Path

from typer.testing import CliRunner

from aipm.app import setup as use_case
from aipm.cli.main import app
from aipm.config import keychain
from aipm.config.loader import load_config, setup_target_path
from tests.fakes.keychain import FakeKeychain
from tests.fakes.secrets import FAKE_SECRETS
from tests.integration.conftest import UserDirs


class Script:
    """Answers by question; records what setup showed."""

    def __init__(self, provider: str, texts: dict[str, str], secret: str = "") -> None:
        self.provider = provider
        self.texts = texts
        self.secret_answer = secret
        self.shown: list[str] = []

    def choose(self, message: str, choices: Sequence[tuple[str, str]], default: str) -> str:
        del message, default
        assert self.provider in {value for _, value in choices}
        return self.provider

    def text(self, message: str, default: str) -> str:
        return self.texts.get(message, default)

    def secret(self, message: str) -> str:
        del message
        return self.secret_answer

    def confirm(self, message: str, default: bool) -> bool:
        del message, default
        return True

    def show(self, line: str) -> None:
        self.shown.append(line)


def test_setup_for_another_provider_is_what_load_config_reads(user_dirs: UserDirs) -> None:
    fake = FakeKeychain()
    keychain.use_backend(fake)
    key = FAKE_SECRETS["OPENAI_API_KEY"]
    script = Script(
        "other",
        {
            "Base URL of the API:": "https://api.deepseek.com",
            "Name of the environment variable that holds the key (the name, not the key):": (
                "DEEPSEEK_API_KEY"
            ),
            "Model for default:": "deepseek-chat",
        },
        secret=key,
    )
    result = use_case.run(script)
    target = setup_target_path()
    assert result.written and Path(result.path) == target
    assert stat.S_IMODE(target.stat().st_mode) == 0o600
    llm = load_config(None).config.llm
    assert llm.provider.value == "openai-compatible"
    assert llm.base_url == "https://api.deepseek.com"
    assert llm.api_key_env == "DEEPSEEK_API_KEY"
    assert llm.models["default"] == "deepseek-chat"
    assert fake.items == {"DEEPSEEK_API_KEY": key}
    assert key not in target.read_text(encoding="utf-8")
    del user_dirs


def test_setup_keeps_other_settings_and_defaults_to_the_current_models(
    user_dirs: UserDirs,
) -> None:
    target = setup_target_path()
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(
        "llm:\n  models: {default: claude-opus-5-5}\nbudget: {run_usd: 3.0}\n", encoding="utf-8"
    )
    use_case.run(Script("anthropic", {}))
    loaded = load_config(None).config
    assert loaded.llm.models["default"] == "claude-opus-5-5"
    assert loaded.budget.run_usd == 3.0
    del user_dirs


def test_setup_with_no_keychain_says_how_to_set_the_key(user_dirs: UserDirs) -> None:
    keychain.use_backend(None)
    script = Script("anthropic", {})
    result = use_case.run(script)
    assert result.keychain is None
    assert any("set ANTHROPIC_API_KEY in your shell" in line for line in script.shown)
    del user_dirs


def test_setup_for_ollama_asks_no_key(user_dirs: UserDirs) -> None:
    fake = FakeKeychain()
    keychain.use_backend(fake)
    script = Script(
        "ollama", {"Model for default:": "llama3.3"}, secret=FAKE_SECRETS["OPENAI_API_KEY"]
    )
    use_case.run(script)
    assert fake.items == {}
    assert load_config(None).config.llm.base_url == "http://localhost:11434/v1"
    del user_dirs


def test_setup_is_listed_and_refuses_without_a_terminal(user_dirs: UserDirs) -> None:
    runner = CliRunner()
    assert "setup" in runner.invoke(app, ["--help"]).output
    result = runner.invoke(app, ["setup"])
    assert result.exit_code == 2
    assert "needs a terminal" in result.output
    del user_dirs
