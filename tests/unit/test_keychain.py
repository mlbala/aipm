"""Keys from the OS keychain: lookup order, caching and doctor's report (ADR-0033)."""

from pathlib import Path

import pytest

from aipm.adapters import claude_code, codex, copilot, gemini
from aipm.app import doctor
from aipm.config import keychain
from aipm.config.schema import LlmConfig
from aipm.domain.errors import UsageError
from aipm.llm.gateway import api_key
from tests.fakes.keychain import FakeKeychain
from tests.fakes.secrets import FAKE_SECRETS

KEY = FAKE_SECRETS["ANTHROPIC_API_KEY"]
OTHER = FAKE_SECRETS["OPENAI_API_KEY"]


def test_agent_key_names_match_every_adapter() -> None:
    adapters = {*claude_code.REQUIRED_ENV, *codex.REQUIRED_ENV, *gemini.REQUIRED_ENV}
    adapters |= {*copilot.REQUIRED_ENV}
    assert set(keychain.AGENT_KEY_NAMES) == adapters


def test_the_environment_comes_first() -> None:
    keychain.use_backend(FakeKeychain({"ANTHROPIC_API_KEY": KEY}))
    keychain.prime(["ANTHROPIC_API_KEY"], {})
    assert keychain.resolve("ANTHROPIC_API_KEY", {"ANTHROPIC_API_KEY": OTHER}) == (
        OTHER,
        "environment",
    )
    assert keychain.resolve("ANTHROPIC_API_KEY", {}) == (KEY, "keychain")


def test_an_empty_environment_value_counts_as_unset() -> None:
    keychain.use_backend(FakeKeychain({"ANTHROPIC_API_KEY": KEY}))
    keychain.prime(["ANTHROPIC_API_KEY"], {})
    assert keychain.resolve("ANTHROPIC_API_KEY", {"ANTHROPIC_API_KEY": ""}) == (KEY, "keychain")


def test_nothing_anywhere_is_unset() -> None:
    keychain.use_backend(FakeKeychain())
    keychain.prime(["ANTHROPIC_API_KEY"], {})
    assert keychain.resolve("ANTHROPIC_API_KEY", {}) == (None, None)


def test_a_differing_environment_value_is_warned() -> None:
    keychain.use_backend(FakeKeychain({"ANTHROPIC_API_KEY": KEY}))
    warnings = keychain.prime(["ANTHROPIC_API_KEY"], {"ANTHROPIC_API_KEY": OTHER})
    assert len(warnings) == 1
    assert "differs" in warnings[0]
    assert KEY not in warnings[0] and OTHER not in warnings[0]


def test_each_name_is_read_once() -> None:
    fake = FakeKeychain({"ANTHROPIC_API_KEY": KEY})
    keychain.use_backend(fake)
    keychain.prime(["ANTHROPIC_API_KEY", "ANTHROPIC_API_KEY"], {})
    keychain.prime(["ANTHROPIC_API_KEY"], {})
    assert fake.asked == ["ANTHROPIC_API_KEY"]


def test_a_failing_backend_counts_as_unset() -> None:
    keychain.use_backend(FakeKeychain({"ANTHROPIC_API_KEY": KEY}, fail=True))
    assert keychain.prime(["ANTHROPIC_API_KEY"], {}) == []
    assert keychain.resolve("ANTHROPIC_API_KEY", {}) == (None, None)


@pytest.mark.parametrize("value", ["short", "has space in it", "line\nbreak-value", "x" * 5000])
def test_an_implausible_value_counts_as_unset(value: str) -> None:
    keychain.use_backend(FakeKeychain({"ANTHROPIC_API_KEY": value}))
    keychain.prime(["ANTHROPIC_API_KEY"], {})
    assert keychain.resolve("ANTHROPIC_API_KEY", {}) == (None, None)


def test_invalid_names_are_never_looked_up() -> None:
    fake = FakeKeychain()
    keychain.use_backend(fake)
    keychain.prime(["bad name", "1X", "A" * 101], {})
    assert fake.asked == []


def test_no_backend_means_environment_only() -> None:
    keychain.use_backend(None)
    assert keychain.prime(["ANTHROPIC_API_KEY"], {}) == []
    assert "not used on this platform" in keychain.describe()
    with pytest.raises(OSError, match="no keychain"):
        keychain.store("ANTHROPIC_API_KEY", KEY)


def test_store_caches_the_value() -> None:
    fake = FakeKeychain()
    keychain.use_backend(fake)
    assert keychain.store("ANTHROPIC_API_KEY", KEY) == "fake keychain"
    assert fake.items == {"ANTHROPIC_API_KEY": KEY}
    assert keychain.resolve("ANTHROPIC_API_KEY", {}) == (KEY, "keychain")
    with pytest.raises(OSError, match="not a variable name"):
        keychain.store("not a name", KEY)


def test_the_gateway_falls_back_to_the_keychain() -> None:
    keychain.use_backend(FakeKeychain({"ANTHROPIC_API_KEY": KEY}))
    keychain.prime(["ANTHROPIC_API_KEY"], {})
    assert api_key(LlmConfig(), {}) == KEY
    keychain.use_backend(None)
    with pytest.raises(UsageError, match="is not set") as raised:
        api_key(LlmConfig(), {})
    assert "aipm setup" in (raised.value.hint or "")


def test_doctor_names_the_source_but_never_the_value(tmp_path: Path) -> None:
    keychain.use_backend(FakeKeychain({"ANTHROPIC_API_KEY": KEY}))
    keychain.prime(["ANTHROPIC_API_KEY"], {})
    report = doctor.run(tmp_path, env={})
    assert report.data["config"]["llm"]["key_sources"]["ANTHROPIC_API_KEY"] == "keychain"  # type: ignore[index]
    assert "  ANTHROPIC_API_KEY: set (fake keychain)" in report.lines
    assert KEY not in "\n".join(report.lines)
    assert KEY not in repr(report.data)
