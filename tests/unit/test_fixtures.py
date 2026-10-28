"""The shared fixtures in tests/conftest.py behave as documented."""

import os
import re
import subprocess
import tomllib
from pathlib import Path

import pytest

from tests.conftest import REPO_ROOT, FakeSecrets
from tests.fakes.secrets import FAKE_SECRETS


def test_tmp_repo_is_a_git_repo_with_one_commit(tmp_repo: Path) -> None:
    log = subprocess.run(
        ["git", "-c", "core.hooksPath=/dev/null", "log", "--format=%s"],
        cwd=tmp_repo,
        capture_output=True,
        text=True,
        check=True,
        timeout=30,
        env={"PATH": os.environ.get("PATH", ""), "GIT_CONFIG_NOSYSTEM": "1"},
    )
    assert log.stdout.splitlines() == ["chore: initial commit"]
    assert (tmp_repo / "README.md").is_file()


def test_fake_secrets_are_in_the_environment(fake_secrets: FakeSecrets) -> None:
    for name, value in FAKE_SECRETS.items():
        assert os.environ[name] == value
    assert fake_secrets.leaked_in("nothing to see") == []


def test_fake_secrets_detects_a_leak(fake_secrets: FakeSecrets) -> None:
    value = FAKE_SECRETS["ANTHROPIC_API_KEY"]
    assert fake_secrets.leaked_in(f"header: Bearer {value}") == ["ANTHROPIC_API_KEY"]
    with pytest.raises(AssertionError):
        fake_secrets.assert_absent(value)


def test_fake_secret_values_match_the_gitleaks_allowlist() -> None:
    """gitleaks allowlists fakes by value, so a real key in tests/fakes/secrets.py is caught."""
    config = tomllib.loads((REPO_ROOT / ".gitleaks.toml").read_text(encoding="utf-8"))
    (pattern,) = config["allowlist"]["regexes"]
    assert "paths" not in config["allowlist"]
    for value in FAKE_SECRETS.values():
        assert re.fullmatch(pattern, value), value
        assert len(value) >= 32
