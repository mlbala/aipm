"""`aipm sync-context` and `aipm approve context` (build prompt 05; ARCHITECTURE §10.2, §16)."""

import json
from collections.abc import Callable
from pathlib import Path

import pytest

from aipm.app import sync_context
from aipm.context.managed_block import BEGIN, END
from aipm.domain.models import ApprovalGate, ApprovalsDoc, ArtifactKind
from aipm.llm.fake import FakeLLM
from tests.integration.flow import aipm, designed, load, ok, planned, trust

FILES = ("AGENTS.md", "CLAUDE.md")


CONTEXT_FILES = [
    "AGENTS.md",
    "CLAUDE.md",
    ".claude/agents/aipm-test-writer.md",
    ".claude/agents/aipm-reviewer.md",
    ".claude/skills/aipm-task-protocol/SKILL.md",
    ".claude/skills/aipm-run-checks/SKILL.md",
]
"""The Claude Code context files, in generation order; the last four arrive in v0.2 (D-3)."""


@pytest.fixture
def repo(tmp_repo: Path, fake_llm: Callable[[str], FakeLLM]) -> Path:
    fake_llm("clinic")
    planned(tmp_repo)
    return tmp_repo


def context_approvals(repo: Path) -> list[str]:
    doc = load(repo, ArtifactKind.APPROVALS, ApprovalsDoc)
    return sorted(a.artifact for a in doc.approvals if a.gate is ApprovalGate.CONTEXT)


def interactive(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr("aipm.cli.output.stdin_is_terminal", lambda: True)


# ---------------------------------------------------------------- trust and preconditions


def test_sync_and_approve_need_trust(tmp_repo: Path, fake_llm: Callable[[str], FakeLLM]) -> None:
    fake_llm("clinic")
    planned(tmp_repo, trusted=False)
    for args in (["sync-context"], ["approve", "context", "--yes"]):
        result = aipm(tmp_repo, *args)
        assert result.exit_code == 6, args
        assert "aipm trust" in result.stderr
        assert "uv run" not in result.stdout
    assert not any((tmp_repo / name).exists() for name in FILES)
    assert context_approvals(tmp_repo) == []


def test_check_needs_no_trust_and_shows_no_argv(
    tmp_repo: Path, fake_llm: Callable[[str], FakeLLM]
) -> None:
    fake_llm("clinic")
    planned(tmp_repo, trusted=False)
    result = aipm(tmp_repo, "sync-context", "--check")
    assert result.exit_code == 3
    assert "out of date: AGENTS.md, CLAUDE.md" in result.stderr
    assert "uv run" not in result.output
    assert json.loads(result.stdout) == {"drift": CONTEXT_FILES}


def test_a_policy_violating_gate_fails_check_with_exit_6(repo: Path) -> None:
    config = repo / ".pm" / "config.yaml"
    text = config.read_text(encoding="utf-8")
    hostile = text.replace("ruff, check, '{paths}'", "ruff, check, -c, x, '{paths}'")
    assert hostile != text
    config.write_text(hostile, encoding="utf-8")
    result = aipm(repo, "sync-context", "--check")
    assert result.exit_code == 6
    assert "gate 'lint' is not allowed by the command policy" in result.stderr
    assert "ruff" not in result.output  # --check runs without trust: no argv in its output
    assert not (repo / "AGENTS.md").exists()
    detailed = aipm(repo, "sync-context")
    assert detailed.exit_code == 6


def test_the_design_must_be_approved(tmp_repo: Path, fake_llm: Callable[[str], FakeLLM]) -> None:
    fake_llm("clinic")
    designed(tmp_repo)
    design = tmp_repo / ".pm" / "architecture.md"
    design.write_text(design.read_text(encoding="utf-8") + "\nChanged.\n", encoding="utf-8")
    trust(tmp_repo)
    result = aipm(tmp_repo, "sync-context")
    assert result.exit_code == 2
    assert "approved, current PRD and design" in result.stderr


def test_other_tools_arrive_later(repo: Path) -> None:
    result = aipm(repo, "sync-context", "--tool", "gemini")
    assert result.exit_code == 2
    assert "v0.4" in result.stderr


# ---------------------------------------------------------------- approval and writing


def test_non_interactive_sync_shows_the_diff_and_needs_approval(repo: Path) -> None:
    result = aipm(repo, "sync-context")
    assert result.exit_code == 4
    assert "AGENTS.md: new file (not approved yet)" in result.stdout
    assert "+++ b/AGENTS.md (managed block)" in result.stdout
    assert "+@AGENTS.md" in result.stdout
    assert "aipm approve context --yes" in result.stderr
    assert not any((repo / name).exists() for name in FILES)


def test_approve_then_sync_writes_both_files(repo: Path) -> None:
    approved = ok(aipm(repo, "approve", "context", "--yes"))
    assert "Context approved." in approved.stdout
    assert not (repo / "AGENTS.md").exists()
    assert context_approvals(repo) == sorted(CONTEXT_FILES)
    written = ok(aipm(repo, "sync-context"))
    assert "Wrote: AGENTS.md, CLAUDE.md" in written.stdout
    agents = (repo / "AGENTS.md").read_text(encoding="utf-8")
    claude = (repo / "CLAUDE.md").read_text(encoding="utf-8")
    assert agents.startswith(f"{BEGIN}\n# Instructions for coding agents: `repo`\n")
    assert agents.endswith(f"{END}\n")
    assert claude.startswith(f"{BEGIN}\n@AGENTS.md\n")
    check = ok(aipm(repo, "sync-context", "--check"))
    assert "Up to date: AGENTS.md, CLAUDE.md" in check.stdout
    again = ok(aipm(repo, "sync-context"))
    assert "Up to date" in again.stdout


def test_interactive_sync_writes_and_records(repo: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    interactive(monkeypatch)
    result = aipm(repo, "sync-context", input="y\n")
    assert result.exit_code == 0, result.output
    assert (repo / "AGENTS.md").is_file()
    assert context_approvals(repo) == sorted(CONTEXT_FILES)


def test_interactive_decline_writes_nothing(repo: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    interactive(monkeypatch)
    result = aipm(repo, "sync-context", input="n\n")
    assert result.exit_code == 0
    assert "Nothing written." in result.stdout
    assert not (repo / "AGENTS.md").exists()
    assert context_approvals(repo) == []


def test_approve_context_needs_yes_without_a_terminal(repo: Path) -> None:
    result = aipm(repo, "approve", "context")
    assert result.exit_code == 4
    assert context_approvals(repo) == []


def test_user_text_outside_the_block_is_kept_byte_for_byte(repo: Path) -> None:
    mine = "# Team notes\r\n\r\nKeep this é line.  \r\n"
    (repo / "AGENTS.md").write_text(mine, encoding="utf-8", newline="")
    tail = "\n## After\nmore notes\n"
    (repo / "CLAUDE.md").write_text(f"# Before\n{BEGIN}\nold\n{END}{tail}", encoding="utf-8")
    ok(aipm(repo, "approve", "context", "--yes"))
    ok(aipm(repo, "sync-context"))
    agents = (repo / "AGENTS.md").read_bytes()
    assert agents.startswith(mine.encode())
    assert b"\r\n# Instructions for coding agents" in agents
    claude = (repo / "CLAUDE.md").read_text(encoding="utf-8")
    assert claude.startswith(f"# Before\n{BEGIN}\n@AGENTS.md\n")
    assert claude.endswith(f"{END}{tail}")


def test_malformed_markers_exit_2_and_write_nothing(repo: Path) -> None:
    broken = f"{BEGIN}\nno end marker\n"
    (repo / "AGENTS.md").write_text(broken, encoding="utf-8")
    result = aipm(repo, "sync-context")
    assert result.exit_code == 2
    assert "AGENTS.md has 1 aipm begin and 0 end markers" in result.stderr
    assert (repo / "AGENTS.md").read_text(encoding="utf-8") == broken
    assert not (repo / "CLAUDE.md").exists()


def test_a_linked_context_file_is_refused(repo: Path, tmp_path: Path) -> None:
    victim = tmp_path / "bashrc"
    victim.write_text("export PATH\n", encoding="utf-8")
    (repo / "AGENTS.md").symlink_to(victim)
    result = aipm(repo, "approve", "context", "--yes")
    assert result.exit_code == 6
    assert victim.read_text(encoding="utf-8") == "export PATH\n"


def test_a_file_changed_after_review_is_not_written(
    repo: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    interactive(monkeypatch)
    real = sync_context.review

    def review_then_edit(project: Path | None, tools: list[str]) -> sync_context.ContextReview:
        shown = real(project, tools)
        (repo / "AGENTS.md").write_text("edited meanwhile\n", encoding="utf-8")
        return shown

    monkeypatch.setattr(sync_context, "review", review_then_edit)
    result = aipm(repo, "sync-context", input="y\n")
    assert result.exit_code == 2
    assert "changed after they were shown" in result.stderr
    assert (repo / "AGENTS.md").read_text(encoding="utf-8") == "edited meanwhile\n"


def test_a_changed_design_makes_check_fail(repo: Path) -> None:
    ok(aipm(repo, "approve", "context", "--yes"))
    ok(aipm(repo, "sync-context"))
    block_edit = (repo / "AGENTS.md").read_text(encoding="utf-8").replace("Keep to", "Ignore")
    (repo / "AGENTS.md").write_text(block_edit, encoding="utf-8")
    result = aipm(repo, "sync-context", "--check")
    assert result.exit_code == 3
    assert "out of date: AGENTS.md" in result.stderr


def test_json_sync(repo: Path) -> None:
    ok(aipm(repo, "approve", "context", "--yes"))
    result = ok(aipm(repo, "sync-context", flags=["--json"]))
    data = json.loads(result.stdout)["data"]
    assert data["written"] == CONTEXT_FILES
    assert [f["action"] for f in data["files"]] == ["create"] * len(CONTEXT_FILES)
