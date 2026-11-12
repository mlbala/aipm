"""Golden snapshots (build prompt 08): the v0.4 context files for the clinic project.

`GEMINI.md` and `.github/copilot-instructions.md` are managed blocks; the Codex skills under
`.agents/skills/` are whole files aipm owns (front matter and body). Their nonces derive from
their content, so the snapshots are byte-stable. Update them only when a template change is
intended, and say so in the commit message (AGENTS.md).
"""

import pytest
from syrupy.assertion import SnapshotAssertion

from aipm.adapters import codex, copilot, gemini
from aipm.context.generator import (
    CODEX_SKILLS,
    claude_extras,
    codex_skills,
    copilot_instructions,
    gemini_md,
)
from aipm.domain.models import GeneratedFile
from tests.fakes.project import clinic_context


@pytest.mark.parametrize("path", sorted(CODEX_SKILLS))
def test_codex_skill(path: str, snapshot: SnapshotAssertion) -> None:
    files = {f.path: f for f in codex_skills(clinic_context())}
    assert files[path].document == snapshot(name=path)


def test_gemini_md(snapshot: SnapshotAssertion) -> None:
    assert gemini_md(clinic_context()).block == snapshot


def test_copilot_instructions(snapshot: SnapshotAssertion) -> None:
    assert copilot_instructions(clinic_context()).block == snapshot


def test_codex_skills_match_the_claude_skills_word_for_word() -> None:
    """One protocol for every tool: the same instructions, only the location differs."""
    claude = {f.path.removeprefix(".claude/"): f.document for f in claude_extras(clinic_context())}
    for f in codex_skills(clinic_context()):
        assert (
            f.document.split("---", 2)[1]
            == claude[f.path.removeprefix(".agents/")].split("---", 2)[1]
        )


@pytest.mark.parametrize(
    ("module", "paths"),
    [
        (codex, ["AGENTS.md", *sorted(CODEX_SKILLS)]),
        (gemini, ["AGENTS.md", "GEMINI.md"]),
        (copilot, ["AGENTS.md", ".github/copilot-instructions.md"]),
    ],
)
def test_each_adapter_lists_its_context_files(module: object, paths: list[str]) -> None:
    files: list[GeneratedFile] = module.create().context_files(clinic_context())  # type: ignore[attr-defined]
    assert sorted(f.path for f in files) == sorted(paths)
