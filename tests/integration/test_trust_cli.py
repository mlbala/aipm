"""`aipm trust` and repo-config limits through the CLI (SECURITY.md §6, invariants I-7, I-8).

- `--yes` never writes trust: `aipm --yes trust` without `--confirm` exits 4 non-interactively.
- `--confirm` with a wrong or stale hash exits 6.
- A repo config that adds a shell gate is rejected by the command policy (exit 6).
"""

import json
import stat
from pathlib import Path
from typing import Any

import pytest
from click.testing import Result
from ruamel.yaml import YAML
from typer.testing import CliRunner

from aipm.app import trust as trust_use_case
from aipm.cli import output
from aipm.cli.main import app
from aipm.state.yamlio import dump_yaml, load_yaml
from tests.integration.conftest import UserDirs

runner = CliRunner()
CORPUS = Path(__file__).parents[1] / "security" / "corpus"


def aipm(repo: Path, *args: str, stdin: str | None = None) -> Result:
    return runner.invoke(app, ["-C", str(repo), *args], input=stdin)


def merge_corpus(repo: Path, name: str) -> dict[str, Any]:
    """Merge a corpus case's hostile config into the repo's `.pm/config.yaml`."""
    case = YAML(typ="safe", pure=True).load((CORPUS / name).read_text(encoding="utf-8"))
    path = repo / ".pm" / "config.yaml"
    base: dict[str, Any] = load_yaml(path.read_text(encoding="utf-8"))  # type: ignore[assignment]
    attack: dict[str, Any] = load_yaml(case["input"]["text"])  # type: ignore[assignment]
    gates = {**base.get("gates", {}), **attack.pop("gates", {})}
    path.write_text(dump_yaml({**base, **attack, "gates": gates}), encoding="utf-8")
    return case


@pytest.fixture
def repo(tmp_repo: Path) -> Path:
    (tmp_repo / "uv.lock").write_text("", encoding="utf-8")
    assert runner.invoke(app, ["-C", str(tmp_repo), "init"]).exit_code == 0
    return tmp_repo


def surface_hash(repo: Path) -> str:
    result = aipm(repo, "--json", "trust", "--show")
    assert result.exit_code == 0, result.output
    return str(json.loads(result.stdout)["data"]["surface_hash"])


def append_config(repo: Path, text: str) -> None:
    path = repo / ".pm" / "config.yaml"
    path.write_text(path.read_text(encoding="utf-8") + text, encoding="utf-8")


def test_show_prints_every_argv_in_full_and_the_hash(repo: Path, user_dirs: UserDirs) -> None:
    result = aipm(repo, "trust", "--show")
    assert result.exit_code == 0, result.output
    digest = surface_hash(repo)
    for line in (
        "uv sync --frozen",
        "uv run --frozen --offline ruff check '{paths}'",
        "uv run --frozen --offline ruff format --check '{paths}'",
        "uv run --frozen --offline pyright '{paths}'",
        "uv run --frozen --offline pytest -q --junitxml '{report_file}' '{test_paths}'",
        f"surface hash: {digest}",
        "trusted: no",
    ):
        assert line in result.stdout
    assert not user_dirs.trust_file.exists()


def test_global_yes_never_writes_trust(repo: Path, user_dirs: UserDirs) -> None:
    result = runner.invoke(app, ["--yes", "-C", str(repo), "trust"])
    assert result.exit_code == 4
    assert "aipm trust --confirm" in result.stderr
    assert not user_dirs.trust_file.exists()
    result = runner.invoke(app, ["-C", str(repo), "trust", "--confirm", "nope", "--show"])
    assert result.exit_code == 0
    assert not user_dirs.trust_file.exists()


@pytest.mark.parametrize("value", ["000000000000", "zzzzzzzzzzzz", "abc", ""])
def test_wrong_confirm_exits_6(repo: Path, user_dirs: UserDirs, value: str) -> None:
    result = aipm(repo, "trust", "--confirm", value)
    assert result.exit_code == 6
    assert not user_dirs.trust_file.exists()


def test_stale_confirm_exits_6(repo: Path, user_dirs: UserDirs) -> None:
    stale = surface_hash(repo)[:12]
    append_config(repo, "dispatch: {default_tool: codex}\n")
    result = aipm(repo, "trust", "--confirm", stale)
    assert result.exit_code == 6
    assert "wrong or stale" in result.stderr
    assert not user_dirs.trust_file.exists()


def test_confirm_records_trust_privately_and_revoke_removes_it(
    repo: Path, user_dirs: UserDirs
) -> None:
    digest = surface_hash(repo)
    result = aipm(repo, "trust", "--confirm", digest[:12].upper())
    assert result.exit_code == 0, result.output
    assert "This surface is trusted." in result.stdout
    assert stat.S_IMODE(user_dirs.trust_file.stat().st_mode) == 0o600
    stored = json.loads(user_dirs.trust_file.read_text(encoding="utf-8"))
    assert [entry["surface_hash"] for entry in stored["repos"].values()] == [digest]
    again = aipm(repo, "trust")
    assert again.exit_code == 0
    assert "trusted: yes" in again.stdout
    append_config(repo, "security: {require_sandbox: true}\n")
    changed = aipm(repo, "--json", "trust", "--show")
    assert json.loads(changed.stdout)["data"]["trusted"] is False
    append_config(repo, "budget: {run_usd: 1}\n")  # not part of the surface
    revoked = aipm(repo, "trust", "--revoke")
    assert revoked.exit_code == 0
    assert "Trust revoked." in revoked.stdout
    assert json.loads(user_dirs.trust_file.read_text(encoding="utf-8"))["repos"] == {}
    assert "was not trusted" in aipm(repo, "trust", "--revoke").stdout


def test_interactive_yes_records_trust(
    repo: Path, user_dirs: UserDirs, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(output, "stdin_is_terminal", lambda: True)
    declined = aipm(repo, "trust", stdin="n\n")
    assert declined.exit_code == 0
    assert "Not trusted." in declined.stdout
    assert not user_dirs.trust_file.exists()
    accepted = aipm(repo, "trust", stdin="y\n")
    assert accepted.exit_code == 0, accepted.output
    assert user_dirs.trust_file.exists()


def test_non_interactive_flag_and_env_disable_prompts(
    repo: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(output, "stdin_is_terminal", lambda: True)
    assert runner.invoke(app, ["--non-interactive", "-C", str(repo), "trust"]).exit_code == 4
    monkeypatch.setenv("AIPM_NON_INTERACTIVE", "1")
    assert aipm(repo, "trust", stdin="y\n").exit_code == 4


def test_corpus_c013_shell_gate_is_rejected_and_relaxations_ignored(
    repo: Path, user_dirs: UserDirs
) -> None:
    case = merge_corpus(repo, "C-013-config-relaxation.yaml")
    user_dirs.config.write_text("security: {require_sandbox: true}\n", encoding="utf-8")
    result = aipm(repo, "trust", "--show")
    assert result.exit_code == case["expected"]["exit_code"] == 6
    assert "gate 'pwn' is not allowed by the command policy" in result.stderr
    assert "security.require_sandbox cannot be relaxed by the repository" in result.stderr
    assert not user_dirs.trust_file.exists()


def test_corpus_c012_redirection_is_ignored_with_warnings(repo: Path, user_dirs: UserDirs) -> None:
    merge_corpus(repo, "C-012-config-redirection.yaml")
    result = aipm(repo, "--json", "trust", "--show")
    assert result.exit_code == 0, result.output
    data = json.loads(result.stdout)["data"]
    assert data["surface"]["extra_allowed_executables"] == []
    assert data["surface"]["dispatch"]["tools"]["claude"]["pass_env"] == []
    assert data["surface"]["dispatch"]["tools"]["claude"]["allow_auto_mode"] is False
    assert ".pm/config.yaml: ignored llm.base_url: it is a user-only key" in data["warnings"]
    assert ".pm/config.yaml: ignored llm.api_key_env: it is a user-only key" in data["warnings"]
    assert "warning: .pm/config.yaml: ignored llm.base_url" in result.stderr


def test_trust_needs_init(tmp_repo: Path) -> None:
    result = aipm(tmp_repo, "trust", "--show")
    assert result.exit_code == 2
    assert "aipm init" in result.stderr


def test_a_damaged_trust_store_fails_closed(repo: Path, user_dirs: UserDirs) -> None:
    user_dirs.trust_file.parent.mkdir(parents=True, exist_ok=True)
    user_dirs.trust_file.write_text("{not json", encoding="utf-8")
    user_dirs.trust_file.chmod(0o600)
    result = aipm(repo, "trust", "--show")
    assert result.exit_code == 6
    assert "damaged" in result.stderr
    user_dirs.trust_file.write_text('{"version": 1, "repos": {}}', encoding="utf-8")
    user_dirs.trust_file.chmod(0o666)
    result = aipm(repo, "trust", "--show")
    assert result.exit_code == 6
    assert "not a private file" in result.stderr


def test_confirm_accepts_more_of_the_hash_and_checks_all_of_it(
    repo: Path, user_dirs: UserDirs
) -> None:
    digest = surface_hash(repo)
    wrong_tail = digest[:12] + ("0" if digest[12] != "0" else "1") + digest[13:]
    assert aipm(repo, "trust", "--confirm", wrong_tail).exit_code == 6
    assert not user_dirs.trust_file.exists()
    assert aipm(repo, "trust", "--confirm", digest).exit_code == 0
    assert user_dirs.trust_file.exists()


def test_interactive_yes_confirms_the_full_hash_it_showed(
    repo: Path, user_dirs: UserDirs, monkeypatch: pytest.MonkeyPatch
) -> None:
    seen: list[str] = []
    real_confirm = trust_use_case.confirm

    def spy(project: Path | None, value: str, **kwargs: Any) -> Any:
        seen.append(value)
        return real_confirm(project, value, **kwargs)

    monkeypatch.setattr(output, "stdin_is_terminal", lambda: True)
    monkeypatch.setattr(trust_use_case, "confirm", spy)
    assert aipm(repo, "trust", stdin="y\n").exit_code == 0
    assert seen == [surface_hash(repo)]
    assert len(seen[0]) == 64


def test_a_path_link_to_a_hard_denied_program_is_refused(
    repo: Path, user_dirs: UserDirs, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    bin_dir = tmp_path / "evil-bin"
    bin_dir.mkdir()
    (bin_dir / "bash").write_text("#!/bin/sh\n", encoding="utf-8")
    (bin_dir / "bash").chmod(0o755)
    (bin_dir / "uv").symlink_to(bin_dir / "bash")
    monkeypatch.setenv("PATH", str(bin_dir))
    result = aipm(repo, "trust", "--show")
    assert result.exit_code == 6
    assert "resolves to the hard-denied program" in result.stderr


def test_test_roots_are_part_of_the_surface(repo: Path) -> None:
    before = surface_hash(repo)
    path = repo / ".pm" / "config.yaml"
    path.write_text(
        path.read_text(encoding="utf-8").replace("test_roots: [tests]", "test_roots: [spec]"),
        encoding="utf-8",
    )
    assert surface_hash(repo) != before
