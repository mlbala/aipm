"""Only the commands that may need a key read the OS keychain (ADR-0033, SECURITY §8).

A locked macOS Keychain can ask for its password on a lookup, so `aipm status` and the other
commands that never call the model or start a coding agent make no lookup at all. A key that
was not read up front is never read later: it is not in the redactor, so it counts as unset.
"""

import logging
import re
from pathlib import Path

import pytest
from typer.testing import CliRunner

from aipm.app import runtime
from aipm.cli.main import app
from aipm.config import keychain
from aipm.observability.redaction import process_redactor
from tests.fakes.keychain import FakeKeychain
from tests.fakes.secrets import FAKE_SECRETS
from tests.integration.conftest import (
    UserDirs,
    user_dirs,  # noqa: F401 - the fixture
)

KEY = FAKE_SECRETS["ANTHROPIC_API_KEY"]
COMMANDS = Path(__file__).resolve().parents[2] / "src" / "aipm" / "cli" / "commands"

NO_KEYS = frozenset(
    {"aipm", "init", "setup", "trust", "approve", "status", "prompt", "sync-context", "scan"}
    | {"task", "merge"}
)
"""The commands that never call the model or start a coding agent (`aipm` is the phase report)."""


def _command_names() -> set[str]:
    names: set[str] = set()
    for source in COMMANDS.glob("*.py"):
        names |= set(re.findall(r'handled\(ctx, "([a-z-]+)"\)', source.read_text("utf-8")))
    return names


def test_every_command_is_decided() -> None:
    """A new command must be put on one side: it reads keys, or it never does."""
    names = _command_names()
    assert names == runtime.KEY_COMMANDS | NO_KEYS
    assert not runtime.KEY_COMMANDS & NO_KEYS


@pytest.mark.parametrize("command", sorted(NO_KEYS))
def test_a_command_that_needs_no_key_reads_no_keychain(
    command: str,
    user_dirs: UserDirs,  # noqa: F811 - the imported fixture
    tmp_path: Path,
) -> None:
    fake = FakeKeychain({"ANTHROPIC_API_KEY": KEY})
    keychain.use_backend(fake)
    runtime.configure(0, tmp_path, command)
    assert fake.asked == []
    assert keychain.resolve("ANTHROPIC_API_KEY", {}) == (None, None)
    assert keychain.resolved_values() == {}
    assert fake.asked == [], "resolve must never fall back to the keychain"
    del user_dirs


@pytest.mark.parametrize("command", sorted(runtime.KEY_COMMANDS))
def test_a_command_that_may_need_a_key_reads_it_and_redacts_it(
    command: str,
    user_dirs: UserDirs,  # noqa: F811 - the imported fixture
    tmp_path: Path,
) -> None:
    fake = FakeKeychain({"ANTHROPIC_API_KEY": KEY})
    keychain.use_backend(fake)
    log_file = runtime.configure(0, tmp_path, command)
    assert "ANTHROPIC_API_KEY" in fake.asked
    assert keychain.resolve("ANTHROPIC_API_KEY", {}) == (KEY, "keychain")
    assert KEY not in process_redactor().redact(f"the key is {KEY} here")
    # The log redactor `configure` builds already knows the key: it was read first.
    logging.getLogger("aipm").warning("the key is %s here", KEY)
    for handler in logging.getLogger("aipm").handlers:
        handler.flush()
    assert log_file is not None
    logged = log_file.read_text(encoding="utf-8")
    assert "the key is" in logged
    assert KEY not in logged
    del user_dirs


def test_a_later_command_without_keys_keeps_the_keys_already_read(
    user_dirs: UserDirs,  # noqa: F811 - the imported fixture
    tmp_path: Path,
) -> None:
    """`auto` runs `approve` inside the same process: the keys it read stay usable."""
    fake = FakeKeychain({"ANTHROPIC_API_KEY": KEY})
    keychain.use_backend(fake)
    runtime.configure(0, tmp_path, "auto")
    runtime.configure(0, tmp_path, "approve")
    assert fake.asked.count("ANTHROPIC_API_KEY") == 1
    assert keychain.resolve("ANTHROPIC_API_KEY", {}) == (KEY, "keychain")
    del user_dirs


def test_no_command_named_still_reads_the_keys(
    user_dirs: UserDirs,  # noqa: F811 - the imported fixture
    tmp_path: Path,
) -> None:
    fake = FakeKeychain({"ANTHROPIC_API_KEY": KEY})
    keychain.use_backend(fake)
    runtime.configure(0, tmp_path)
    assert "ANTHROPIC_API_KEY" in fake.asked
    del user_dirs


def test_status_from_the_cli_reads_no_keychain_but_doctor_does(
    user_dirs: UserDirs,  # noqa: F811 - the imported fixture
    tmp_path: Path,
) -> None:
    fake = FakeKeychain({"ANTHROPIC_API_KEY": KEY})
    keychain.use_backend(fake)
    runner = CliRunner()
    for args in (["status"], []):
        result = runner.invoke(app, ["-C", str(tmp_path), *args])
        assert "is not inside a git repository" in result.output  # the command really ran
    assert fake.asked == []
    result = runner.invoke(app, ["-C", str(tmp_path), "doctor"])
    assert "ANTHROPIC_API_KEY" in fake.asked
    assert KEY not in result.output
    del user_dirs
