"""The owner's decisions on the v0.4 review's open items (docs/security/reviews/v0.4.md §6.3;
docs/security/reviews/v0.4-decisions-progress.md).

One section per decision. Every test in a section failed before its change.
"""

from collections.abc import Iterator
from pathlib import Path

import pytest
from typer.testing import CliRunner

from aipm.cli.main import app
from aipm.config import locations
from aipm.config.loader import load_config, user_redact_patterns
from aipm.config.schema import Config
from aipm.domain.errors import PolicyViolation

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
    monkeypatch.setattr(locations, "account_home", lambda: str(home))
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


# ---------------------------------------------------------------- v0.1 O-2: a missing AIPM_CONFIG


def test_aipm_config_naming_a_missing_file_exits_6(isolated: Path, tmp_path: Path) -> None:
    del isolated
    missing = tmp_path / "nowhere" / "config.yaml"
    with pytest.raises(PolicyViolation, match="does not exist"):
        load_config(None, env={"AIPM_CONFIG": str(missing)})
    with pytest.raises(PolicyViolation, match="does not exist"):
        user_redact_patterns(None, env={"AIPM_CONFIG": str(missing)})


def test_aipm_config_naming_a_dangling_link_exits_6(isolated: Path, tmp_path: Path) -> None:
    del isolated
    link = tmp_path / "config.yaml"
    link.symlink_to(tmp_path / "gone.yaml")
    with pytest.raises(PolicyViolation, match="does not exist"):
        load_config(None, env={"AIPM_CONFIG": str(link)})


def test_the_cli_exits_6_for_a_missing_aipm_config(
    isolated: Path, tmp_repo: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    del isolated
    monkeypatch.setenv("AIPM_CONFIG", str(tmp_path / "missing.yaml"))
    result = runner.invoke(app, ["-C", str(tmp_repo), "init"])
    assert result.exit_code == 6, result.output
    assert "AIPM_CONFIG" in result.stderr
    assert not (tmp_repo / ".pm").exists()


def test_a_missing_default_user_config_is_still_fine(isolated: Path) -> None:
    """A new user has no config file; only an explicit `AIPM_CONFIG` must exist."""
    del isolated
    assert load_config(None, env={}).config == Config()
    assert load_config(None, env={"AIPM_CONFIG": ""}).config == Config()


# ---------------------------------------------------------------- v0.1 O-1 (B): moved directories


def _env(home: Path, **extra: str) -> dict[str, str]:
    return {"HOME": str(home), **extra}


def test_no_location_warning_for_the_account_home(isolated: Path) -> None:
    assert locations.location_warnings(_env(isolated)) == []


def test_aipm_config_is_warned_on_every_run(isolated: Path, tmp_path: Path) -> None:
    user = tmp_path / "user.yaml"
    (found,) = locations.location_warnings(_env(isolated, AIPM_CONFIG=str(user)))
    assert "AIPM_CONFIG" in found
    assert str(user) in found


def test_a_home_other_than_the_account_home_is_warned(isolated: Path, tmp_path: Path) -> None:
    other = tmp_path / "other-home"
    other.mkdir()
    (found,) = locations.location_warnings(_env(other))
    assert "HOME" in found
    assert str(other) in found
    assert str(isolated) in found


def test_the_same_home_through_a_link_is_not_warned(isolated: Path, tmp_path: Path) -> None:
    link = tmp_path / "home-link"
    link.symlink_to(isolated)
    assert locations.location_warnings(_env(link)) == []


def test_an_unknown_account_home_is_warned(isolated: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(locations, "account_home", lambda: None)
    (found,) = locations.location_warnings(_env(isolated))
    assert "cannot look up" in found


@pytest.mark.parametrize(
    "name", ["AIPM_CONFIG", "XDG_CONFIG_HOME", "XDG_STATE_HOME", "XDG_CACHE_HOME"]
)
def test_a_directory_inside_a_git_work_tree_is_warned(
    isolated: Path, tmp_repo: Path, name: str
) -> None:
    target = tmp_repo / "sub" / ("config.yaml" if name == "AIPM_CONFIG" else "dir")
    found = locations.location_warnings(_env(isolated, **{name: str(target)}))
    assert any(name in w and "git work tree" in w and str(tmp_repo) in w for w in found), found


def test_xdg_data_home_and_directories_outside_work_trees_are_not_warned(
    isolated: Path, tmp_repo: Path, tmp_path: Path
) -> None:
    env = _env(
        isolated,
        XDG_DATA_HOME=str(tmp_repo / "data"),
        XDG_CONFIG_HOME=str(tmp_path / "xdg_config_home"),
        XDG_STATE_HOME="",
    )
    assert locations.location_warnings(env) == []


def test_the_cli_prints_location_warnings_on_stderr(
    isolated: Path, tmp_repo: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    del isolated
    monkeypatch.setenv("XDG_STATE_HOME", str(tmp_repo / "state"))
    result = runner.invoke(app, ["--json", "-C", str(tmp_path / "outside"), "doctor"])
    assert "warning: XDG_STATE_HOME" in result.stderr
    assert "XDG_STATE_HOME" not in result.stdout
