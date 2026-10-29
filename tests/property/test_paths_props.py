"""Property tests for path validation (§20): no accepted input escapes or names a protected path.

The glob oracle here is written independently of `aipm.security.paths`: `*` and `?` stay inside
one component, and `**` matches anything, which over-approximates real glob matching.
"""

import os
import re
from pathlib import Path

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st

from aipm.domain.errors import PolicyViolation
from aipm.security.paths import is_protected, safe_rel_glob, safe_relpath

PATH_PARTS = st.sampled_from(
    [
        "src", "app.py", "tests", "..", ".", "", "-rf", "--x", ".pm", ".PM", ".git", ".git.",
        ".github", ".env", ".env.local", "AGENTS.md", "link_out", "link_root", "link_pm",
        "inside", "~", "a\x00b", "a\\b", "C:", "x\u200b", "deep",
    ]
)  # fmt: skip
GLOB_PARTS = st.sampled_from(
    [
        "src", "tests", "**", "*", "*.py", "*.md", "?", "??", ".pm", ".PM", ".git", ".github",
        ".env", ".env*", "AGENTS.md", "agents.md", ".*", ".p?", "..", ".", "", "-x", "a?b", "x*",
        ".claude", "CLAUDE.md", "*.yml",
    ]
)  # fmt: skip

# Concrete protected paths; an accepted glob must match none of them.
PROTECTED_SAMPLES = [
    ".pm", ".pm/tasks.yaml", ".git", ".git/config", ".github/workflows/ci.yml",
    ".gitlab-ci.yml", "AGENTS.md", "CLAUDE.md", "GEMINI.md", ".claude/settings.json",
    ".gemini/settings.json", ".codex/config.toml", ".agents/skills/x.md", ".mcp.json",
    ".gitattributes", ".gitmodules", ".aipmignore", ".env", ".env.local",
]  # fmt: skip


def oracle(glob: str) -> re.Pattern[str]:
    pieces: list[str] = []
    for index, part in enumerate(glob.split("/")):
        if index:
            pieces.append("/")
        if part == "**":
            pieces.append(".*")
            continue
        for ch in part:
            pieces.append("[^/]*" if ch == "*" else "[^/]" if ch == "?" else re.escape(ch))
    return re.compile("".join(pieces), re.IGNORECASE | re.DOTALL)


@pytest.fixture(scope="module")
def workspace(tmp_path_factory: pytest.TempPathFactory) -> Path:
    base = tmp_path_factory.mktemp("paths")
    root = base / "ws"
    (root / "src" / "deep").mkdir(parents=True)
    (root / ".pm").mkdir()
    (base / "outside").mkdir()
    (root / "link_out").symlink_to(base / "outside")
    (root / "link_root").symlink_to(root)
    (root / "src" / "link_pm").symlink_to(Path("..") / ".pm")
    (root / "src" / "deep" / "link_out").symlink_to(Path("..") / ".." / "..")
    (root / "inside").symlink_to(Path("src"))
    return root


@settings(max_examples=600, deadline=None)
@given(st.lists(PATH_PARTS, min_size=1, max_size=6), st.booleans())
def test_safe_relpath_never_accepts_an_escaping_path(
    workspace: Path, parts: list[str], leading_slash: bool
) -> None:
    candidate = ("/" if leading_slash else "") + "/".join(parts)
    try:
        rel = safe_relpath(workspace, candidate)
    except PolicyViolation:
        return
    root_real = os.path.realpath(workspace)
    target = os.path.realpath(workspace / rel)
    assert target.startswith(root_real + os.sep), (candidate, target)
    resolved = os.path.relpath(target, root_real)
    assert not is_protected(resolved), (candidate, resolved)
    assert ".." not in rel.split("/")
    assert not rel.startswith(("-", "/"))
    assert "\x00" not in rel


@settings(max_examples=800, deadline=None)
@given(st.lists(GLOB_PARTS, min_size=1, max_size=5), st.booleans())
def test_safe_rel_glob_never_accepts_a_protected_or_escaping_glob(
    parts: list[str], leading_slash: bool
) -> None:
    candidate = ("/" if leading_slash else "") + "/".join(parts)
    try:
        glob = safe_rel_glob(candidate)
    except PolicyViolation:
        return
    assert ".." not in glob.split("/")
    assert not glob.startswith(("-", "/"))
    matcher = oracle(glob)
    hits = [sample for sample in PROTECTED_SAMPLES if matcher.fullmatch(sample)]
    assert hits == [], (candidate, hits)
