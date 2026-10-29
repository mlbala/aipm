"""`aipm doctor` (build prompt 02 step 11): versions, keys present, schema, lock, trust, JSON."""

import json
from pathlib import Path

import pytest
from click.testing import Result
from typer.testing import CliRunner

from aipm.cli.main import app
from tests.conftest import FakeSecrets

runner = CliRunner()


@pytest.fixture
def stub_path(tmp_path: Path) -> Path:
    """A directory with only a fake `git` and a fake `uv` whose version line has an escape."""
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    for name, line in (("git", "git version 2.99.0"), ("uv", "uv 9.9.9 \\033[31mred")):
        script = bin_dir / name
        script.write_text(f'#!/bin/sh\nprintf "{line}\\n"\n', encoding="utf-8")
        script.chmod(0o755)
    return bin_dir


def doctor(monkeypatch: pytest.MonkeyPatch, stub_path: Path, *args: str) -> Result:
    """Run doctor with PATH holding only the stubs (set late: tmp_repo needs the real git)."""
    monkeypatch.setenv("PATH", str(stub_path))
    return runner.invoke(app, [*args, "doctor"])


def test_doctor_json_shape(
    stub_path: Path, tmp_repo: Path, fake_secrets: FakeSecrets, monkeypatch: pytest.MonkeyPatch
) -> None:
    assert runner.invoke(app, ["-C", str(tmp_repo), "init"]).exit_code == 0
    result = doctor(monkeypatch, stub_path, "--json", "-C", str(tmp_repo))
    assert result.exit_code == 0, result.output
    lines = result.stdout.splitlines()
    assert len(lines) == 1
    env = json.loads(lines[0])
    assert env["ok"] is True
    assert env["command"] == "doctor"
    data = env["data"]
    assert set(data) == {
        "aipm", "tools", "keys", "repo", "config", "schema", "lock", "trust", "sandbox", "plugins",
    }  # fmt: skip
    tools = {tool["name"]: tool for tool in data["tools"]}
    assert set(tools) == {
        "git", "uv", "claude", "codex", "copilot", "gemini", "srt", "semgrep", "gitleaks",
        "osv-scanner", "trivy",
    }  # fmt: skip
    assert tools["git"]["found"] is True
    assert tools["git"]["version"] == "git version 2.99.0"
    assert tools["uv"]["version"] == "uv 9.9.9 red"
    assert tools["claude"] == {"name": "claude", "found": False, "path": None, "version": None}
    assert data["keys"]["ANTHROPIC_API_KEY"] is True
    assert data["keys"]["GEMINI_API_KEY"] is False
    fake_secrets.assert_absent(result.stdout)
    assert data["repo"]["initialized"] is True
    assert data["config"]["ok"] is True
    assert data["schema"]["repo-map.md"] == "ok"
    assert data["schema"]["tasks.yaml"] == "missing"
    assert data["lock"] == {"held": False, "detail": None}
    assert data["trust"]["trusted"] is False
    assert len(data["trust"]["surface_hash"]) == 64
    assert data["sandbox"] == {"srt": False, "require_sandbox": False}
    assert data["plugins"]["enabled"] is False


def test_doctor_human_output_outside_a_repo(
    stub_path: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    result = doctor(monkeypatch, stub_path, "-C", str(tmp_path))
    assert result.exit_code == 0, result.output
    assert "git version 2.99.0" in result.stdout
    assert "codex        missing" in result.stdout
    assert "Repository: not inside a git repository" in result.stdout
    assert "\x1b" not in result.stdout


def test_doctor_reports_a_broken_artifact_and_config(
    stub_path: Path, tmp_repo: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    assert runner.invoke(app, ["-C", str(tmp_repo), "init"]).exit_code == 0
    (tmp_repo / ".pm" / "tasks.yaml").write_text("schema_version: 9\n", encoding="utf-8")
    config = tmp_repo / ".pm" / "config.yaml"
    config.write_text(config.read_text(encoding="utf-8") + "telemetry: true\n", encoding="utf-8")
    result = doctor(monkeypatch, stub_path, "--json", "-C", str(tmp_repo))
    assert result.exit_code == 0
    data = json.loads(result.stdout)["data"]
    assert "schema_version 9" in data["schema"]["tasks.yaml"]
    assert data["config"]["ok"] is False
    assert "telemetry" in data["config"]["error"]
    assert data["trust"] is None


def test_doctor_does_not_need_the_network_or_an_llm(
    stub_path: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    for name in ("ANTHROPIC_API_KEY", "OPENAI_API_KEY"):
        monkeypatch.delenv(name, raising=False)
    result = doctor(monkeypatch, stub_path, "-C", str(tmp_path))
    assert result.exit_code == 0
