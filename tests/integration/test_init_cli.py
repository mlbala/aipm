"""`aipm init` end to end (build prompt 02 step 11), with golden output per stack template."""

import json
from pathlib import Path

import pytest
from click.testing import Result
from syrupy.assertion import SnapshotAssertion
from typer.testing import CliRunner

from aipm.cli.main import app
from aipm.config.loader import load_config
from aipm.domain.models import ArtifactKind, Mode, RepoMapDoc
from aipm.state.store import open_store
from tests.integration.conftest import UserDirs

runner = CliRunner()


def init(repo: Path, *args: str) -> Result:
    return runner.invoke(app, ["-C", str(repo), "init", *args])


@pytest.fixture
def python_repo(tmp_repo: Path) -> Path:
    """The temporary repo plus a small uv project, a secret file and an ignored directory."""
    (tmp_repo / "pyproject.toml").write_text('[project]\nname = "sample"\n', encoding="utf-8")
    (tmp_repo / "uv.lock").write_text("version = 1\n", encoding="utf-8")
    (tmp_repo / "src" / "sample").mkdir(parents=True)
    (tmp_repo / "src" / "sample" / "__init__.py").write_text("", encoding="utf-8")
    (tmp_repo / "tests").mkdir()
    (tmp_repo / "tests" / "test_sample.py").write_text("def test_x(): pass\n", encoding="utf-8")
    (tmp_repo / ".env").write_text("TOKEN=not-a-real-one\n", encoding="utf-8")
    (tmp_repo / ".gitignore").write_text("build/\n", encoding="utf-8")
    (tmp_repo / "build").mkdir()
    (tmp_repo / "build" / "artifact.txt").write_text("x", encoding="utf-8")
    return tmp_repo


def test_init_outside_a_git_repo_exits_2_and_suggests_git_init(tmp_path: Path) -> None:
    result = runner.invoke(app, ["-C", str(tmp_path), "init"])
    assert result.exit_code == 2
    assert "is not inside a git repository" in result.stderr
    assert "git init" in result.stderr
    assert not (tmp_path / ".pm").exists()


def test_init_in_an_empty_repo(tmp_repo: Path, snapshot: SnapshotAssertion) -> None:
    result = init(tmp_repo)
    assert result.exit_code == 0, result.output
    assert "(greenfield)" in result.stdout
    assert "Stack template: none" in result.stdout
    assert "aipm trust --confirm" in result.stdout
    pm = tmp_repo / ".pm"
    assert sorted(p.name for p in pm.iterdir()) == [
        ".gitignore",
        ".lock",
        "config.yaml",
        "repo-map.md",
    ]
    config_text = (pm / "config.yaml").read_text(encoding="utf-8")
    repo_map_text = (pm / "repo-map.md").read_text(encoding="utf-8")
    assert config_text == snapshot(name="config.yaml")
    assert repo_map_text == snapshot(name="repo-map.md")
    loaded = load_config(tmp_repo)
    assert loaded.config.stack_template is None
    assert loaded.config.gates == {}
    repo_map = open_store(tmp_repo).load(ArtifactKind.REPO_MAP)
    assert isinstance(repo_map, RepoMapDoc)
    assert repo_map.meta.mode is Mode.GREENFIELD


def test_init_in_a_python_uv_repo(python_repo: Path, snapshot: SnapshotAssertion) -> None:
    result = init(python_repo)
    assert result.exit_code == 0, result.output
    assert "(brownfield)" in result.stdout
    assert "Stack template: python-uv" in result.stdout
    assert "uv run --frozen --offline pytest -q --junitxml" in result.stdout
    pm = python_repo / ".pm"
    config_text = (pm / "config.yaml").read_text(encoding="utf-8")
    repo_map_text = (pm / "repo-map.md").read_text(encoding="utf-8")
    assert config_text == snapshot(name="config.yaml")
    assert repo_map_text == snapshot(name="repo-map.md")
    assert ".env" not in repo_map_text
    assert "build/" not in repo_map_text
    cfg = load_config(python_repo).config
    assert cfg.stack_template == "python-uv"
    assert set(cfg.gates) >= {"lint", "unit", "secrets", "ac_trace"}
    assert cfg.project.name == "repo"


def test_init_json_envelope_and_no_trust_without_confirmation(
    python_repo: Path, user_dirs: UserDirs
) -> None:
    result = runner.invoke(app, ["--json", "--yes", "-C", str(python_repo), "init"])
    assert result.exit_code == 0, result.output
    lines = result.stdout.splitlines()
    assert len(lines) == 1
    data = json.loads(lines[0])["data"]
    assert data["stack_template"] == "python-uv"
    assert data["trusted"] is False
    assert len(data["surface_hash"]) == 64
    assert not user_dirs.trust_file.exists()


def test_second_init_needs_force_and_force_keeps_artifacts(tmp_repo: Path) -> None:
    assert init(tmp_repo).exit_code == 0
    again = init(tmp_repo)
    assert again.exit_code == 2
    assert "--force" in again.stderr
    requirements = tmp_repo / ".pm" / "requirements.yaml"
    requirements.write_text("schema_version: 1\n", encoding="utf-8")
    (tmp_repo / "uv.lock").write_text("", encoding="utf-8")
    forced = init(tmp_repo, "--force")
    assert forced.exit_code == 0, forced.output
    assert "Kept: requirements.yaml" in forced.stdout
    assert requirements.read_text(encoding="utf-8") == "schema_version: 1\n"
    assert load_config(tmp_repo).config.stack_template == "python-uv"


@pytest.mark.parametrize(
    ("args", "message"),
    [
        (["--stack", "node-npm"], "unknown stack template"),
        (["--tool", "cursor"], "unknown tool"),
        (["--provider", "evil"], "unknown provider"),
    ],
)
def test_bad_flags_exit_2_before_writing(tmp_repo: Path, args: list[str], message: str) -> None:
    result = init(tmp_repo, *args)
    assert result.exit_code == 2
    assert message in result.stderr
    assert not (tmp_repo / ".pm").exists()


def test_tool_and_provider_flags(tmp_repo: Path) -> None:
    result = init(tmp_repo, "--tool", "codex", "--provider", "openai-compatible")
    assert result.exit_code == 0, result.output
    assert "user-only key" in result.stdout
    text = (tmp_repo / ".pm" / "config.yaml").read_text(encoding="utf-8")
    assert "default_tool: codex" in text
    assert "provider" not in text


def test_detected_but_unshipped_stack_is_reported(tmp_repo: Path) -> None:
    (tmp_repo / "package.json").write_text("{}", encoding="utf-8")
    result = init(tmp_repo)
    assert result.exit_code == 0, result.output
    assert "detected the node-npm stack" in result.stdout
    assert load_config(tmp_repo).config.gates == {}


def test_hostile_file_names_never_reach_the_repo_map_or_terminal(tmp_repo: Path) -> None:
    (tmp_repo / "evil\x1b]52;c;ZXZpbA==\x07.py").write_text("", encoding="utf-8")
    (tmp_repo / "bidi\u202egnp.exe").write_text("", encoding="utf-8")
    (tmp_repo / "README.md").write_text("# Title \x1b[31mred\u200b\n", encoding="utf-8")
    result = init(tmp_repo)
    assert result.exit_code == 0, result.output
    text = (tmp_repo / ".pm" / "repo-map.md").read_text(encoding="utf-8")
    assert "\x1b" not in text and "\u202e" not in text and "\u200b" not in text
    assert "2 entries with unusual names were left out." in text
    assert "README heading: Title red" in text
    assert "\x1b" not in result.output


def test_init_from_a_subdirectory_uses_the_repo_root(python_repo: Path) -> None:
    result = runner.invoke(app, ["-C", str(python_repo / "src"), "init"])
    assert result.exit_code == 0, result.output
    assert (python_repo / ".pm" / "config.yaml").exists()
    assert not (python_repo / "src" / ".pm").exists()
