"""Integration fixtures: every CLI test runs with its own home, config, state and cache dirs,
and from an empty working directory.

The CLI writes logs and the trust store to the user state directory and reads the user config,
so no integration test may touch the real ones, nor the repository the tests run from.
"""

from collections.abc import Iterator
from dataclasses import dataclass
from pathlib import Path

import platformdirs
import pytest


@dataclass(frozen=True)
class UserDirs:
    """The isolated per-user locations for one test."""

    home: Path
    config: Path

    @property
    def trust_file(self) -> Path:
        return Path(platformdirs.user_state_dir("aipm", appauthor=False)) / "trust.json"


@pytest.fixture(autouse=True)
def user_dirs(
    tmp_path_factory: pytest.TempPathFactory, monkeypatch: pytest.MonkeyPatch
) -> Iterator[UserDirs]:
    base = tmp_path_factory.mktemp("user")
    home = base / "home"
    home.mkdir()
    monkeypatch.setenv("HOME", str(home))
    for name in ("XDG_CONFIG_HOME", "XDG_STATE_HOME", "XDG_CACHE_HOME", "XDG_DATA_HOME"):
        monkeypatch.setenv(name, str(base / name.lower()))
    config = base / "user-config.yaml"
    monkeypatch.setenv("AIPM_CONFIG", str(config))
    for name in ("AIPM_NON_INTERACTIVE", "AIPM_LOG_LEVEL"):
        monkeypatch.delenv(name, raising=False)
    # A command run without -C must never land in the aipm checkout itself.
    monkeypatch.chdir(base)
    yield UserDirs(home=home, config=config)
