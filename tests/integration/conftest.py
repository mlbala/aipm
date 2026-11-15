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

from aipm.config import locations
from aipm.config.loader import user_config_path


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
    # The temporary HOME is this test's account home: without this, every command would warn
    # that HOME is not the account's home (v0.1 O-1). In-process only; no variable can do it.
    monkeypatch.setattr(locations, "account_home", lambda: str(home))
    for name in ("XDG_CONFIG_HOME", "XDG_STATE_HOME", "XDG_CACHE_HOME", "XDG_DATA_HOME"):
        monkeypatch.setenv(name, str(base / name.lower()))
    # An empty user config ("no user settings") at the default location under the temporary
    # config directory. AIPM_CONFIG stays unset, as for most users: aipm warns on every run
    # when it is set (v0.1 O-1).
    monkeypatch.delenv("AIPM_CONFIG", raising=False)
    config = user_config_path({})
    config.parent.mkdir(parents=True, exist_ok=True)
    config.write_text("", encoding="utf-8")
    for name in ("AIPM_NON_INTERACTIVE", "AIPM_LOG_LEVEL"):
        monkeypatch.delenv(name, raising=False)
    # A command run without -C must never land in the aipm checkout itself.
    monkeypatch.chdir(base)
    yield UserDirs(home=home, config=config)
