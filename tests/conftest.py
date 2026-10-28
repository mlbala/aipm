"""Shared test fixtures.

Tests never use the network (`--disable-socket`) or a real LLM. Subprocesses here (git, the
CLI, ruff, lint-imports) are test tooling; aipm itself starts processes only through
`aipm.execution.process`.
"""

import os
import subprocess
from collections.abc import Mapping
from dataclasses import dataclass, field
from pathlib import Path

import pytest

from tests.fakes.secrets import FAKE_SECRETS

REPO_ROOT = Path(__file__).resolve().parents[1]


def pytest_collection_modifyitems(config: pytest.Config, items: list[pytest.Item]) -> None:
    """Skip timing tests on CI runners and live tests unless asked for."""
    del config
    skip_timing = os.environ.get("CI") and os.environ.get("AIPM_RUN_TIMING") != "1"
    skip_live = os.environ.get("AIPM_LIVE") != "1"
    for item in items:
        if skip_timing and "timing" in item.keywords:
            item.add_marker(
                pytest.mark.skip(reason="timing test skipped on CI; set AIPM_RUN_TIMING=1")
            )
        if skip_live and "live" in item.keywords:
            item.add_marker(pytest.mark.skip(reason="live test; set AIPM_LIVE=1 to run"))


def _git_env(home: Path) -> dict[str, str]:
    """A constructed environment: no user or system git config, no hooks."""
    return {
        "PATH": os.environ.get("PATH", ""),
        "HOME": str(home),
        "LANG": "C",
        "GIT_CONFIG_GLOBAL": os.devnull,
        "GIT_CONFIG_NOSYSTEM": "1",
    }


@pytest.fixture
def tmp_repo(tmp_path: Path) -> Path:
    """A temporary git repository on `main` with one commit."""
    repo = tmp_path / "repo"
    home = tmp_path / "home"
    repo.mkdir()
    home.mkdir()
    env = _git_env(home)

    def git(*args: str) -> None:
        subprocess.run(
            [
                "git",
                "-c", "core.hooksPath=/dev/null",
                "-c", "commit.gpgsign=false",
                "-c", "user.name=aipm test",
                "-c", "user.email=test@example.invalid",
                *args,
            ],
            cwd=repo,
            env=env,
            check=True,
            capture_output=True,
            timeout=30,
        )  # fmt: skip

    git("init", "-q", "-b", "main")
    (repo / "README.md").write_text("# sample project\n", encoding="utf-8")
    git("add", "README.md")
    git("commit", "-q", "-m", "chore: initial commit")
    return repo


@dataclass(frozen=True)
class FakeSecrets:
    """The fake secrets registered in the environment for one test."""

    values: Mapping[str, str] = field(default_factory=lambda: dict(FAKE_SECRETS))

    def leaked_in(self, text: str) -> list[str]:
        """Return the names of the fake secrets that appear in `text`."""
        return [name for name, value in self.values.items() if value in text]

    def assert_absent(self, text: str) -> None:
        """Fail if any fake secret appears in `text`."""
        leaked = self.leaked_in(text)
        assert not leaked, f"fake secrets leaked: {leaked}"


@pytest.fixture
def fake_secrets(monkeypatch: pytest.MonkeyPatch) -> FakeSecrets:
    """Register the fake secrets as environment variables and expose them."""
    for name, value in FAKE_SECRETS.items():
        monkeypatch.setenv(name, value)
    return FakeSecrets()


@pytest.fixture
def fake_llm() -> None:
    """Placeholder until build prompt 03 adds `aipm.llm.fake.FakeLLM`."""
    pytest.skip("FakeLLM arrives in build prompt 03 (aipm.llm.fake)")
