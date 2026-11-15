"""The owner's decisions on the v0.4 review's open items (docs/security/reviews/v0.4.md §6.3;
docs/security/reviews/v0.4-decisions-progress.md).

One section per decision. Every test in a section failed before its change.
"""

from collections.abc import Iterator
from pathlib import Path

import pytest
from typer.testing import CliRunner

from aipm.cli.main import app

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
