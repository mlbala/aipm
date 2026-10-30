"""aipm's Claude Code subagents and skills (ARCHITECTURE §10.2; SECURITY.md §14.1 I-2, I-3).

Fixed front matter (no `allowed-tools` in a skill; the reviewer may only read), instructions
only (no script anywhere), every interpolated field sanitized, gate argv only from
`compile_gate`, and invariant I-3 held whatever the approved artifacts say. aipm owns these
files whole; their directories are created without ever following a link.
"""

from pathlib import Path

import pytest
from hypothesis import given, settings

from aipm.context.generator import CLAUDE_EXTRAS, agents_md, claude_extras
from aipm.context.markdown import agent_text_problems
from aipm.domain.errors import PolicyViolation
from aipm.security.untrusted import check_blocks
from aipm.state.repo_files import make_repo_dirs
from tests.fakes.project import clinic_context, hostile_context
from tests.security.test_context_files import FIELD


def front_matter(document: str) -> dict[str, str]:
    assert document.startswith("---\n")
    head = document.split("\n---\n", 1)[0].removeprefix("---\n")
    return dict(line.split(": ", 1) for line in head.splitlines())


def test_front_matter_is_fixed_and_tools_are_limited() -> None:
    files = {f.path: f for f in claude_extras(clinic_context())}
    reviewer = front_matter(files[".claude/agents/aipm-reviewer.md"].document)
    assert reviewer["tools"] == "Read, Grep, Glob"
    writer = front_matter(files[".claude/agents/aipm-test-writer.md"].document)
    assert set(writer) == {"name", "description", "tools"}
    for path in (".claude/skills/aipm-task-protocol/SKILL.md",
                 ".claude/skills/aipm-run-checks/SKILL.md"):  # fmt: skip
        skill = front_matter(files[path].document)
        assert set(skill) == {"name", "description"}, "no allowed-tools in a skill"
    for generated in files.values():
        assert generated.preamble is not None
        assert front_matter(generated.document)["name"] == Path(generated.path).stem.replace(
            "SKILL", Path(generated.path).parent.name
        )


def test_instructions_only() -> None:
    assert all(path.endswith(".md") for path in CLAUDE_EXTRAS)
    skills = [p for p in CLAUDE_EXTRAS if p.startswith(".claude/skills/")]
    assert all(p.endswith("/SKILL.md") for p in skills)
    for generated in claude_extras(clinic_context()):
        assert "```" not in generated.block, "no code blocks to run"


def test_the_checks_skill_shows_the_trusted_gate_argv_only() -> None:
    ctx = clinic_context()
    checks = next(f for f in claude_extras(ctx) if f.path.endswith("aipm-run-checks/SKILL.md"))
    agents = agents_md(ctx).block
    lines = [line for line in checks.block.splitlines() if line.startswith("- `")]
    assert lines, "the commands are listed"
    for line in lines:
        assert line in agents, "every command line is the one AGENTS.md shows (compile_gate)"


@settings(max_examples=100, deadline=None)
@given(FIELD)
def test_every_extra_keeps_invariant_i3(text: str) -> None:
    for generated in claude_extras(hostile_context(text)):
        assert agent_text_problems(generated.document, allowed_url_domains=()) == []
        check_blocks(generated.block)


def test_directories_are_created_without_following_links(tmp_path: Path) -> None:
    make_repo_dirs(tmp_path, ".claude/skills/aipm-run-checks/SKILL.md")
    assert (tmp_path / ".claude" / "skills" / "aipm-run-checks").is_dir()
    other = tmp_path / "other"
    other.mkdir()
    linked = tmp_path / "linked"
    linked.mkdir()
    (linked / ".claude").symlink_to(other)
    with pytest.raises(PolicyViolation):
        make_repo_dirs(linked, ".claude/agents/aipm-reviewer.md")
    assert list(other.iterdir()) == []
    with pytest.raises(Exception, match="plain relative path"):
        make_repo_dirs(tmp_path, "../x/y.md")
