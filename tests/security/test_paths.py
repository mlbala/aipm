"""Path validation (SECURITY.md §7.4, §9.2, §10 rule 5; corpus C-009)."""

import os
from pathlib import Path

import pytest
from ruamel.yaml import YAML

from aipm.domain.errors import ExitCode, PolicyViolation
from aipm.security.paths import (
    PROTECTED_PATHS,
    is_protected,
    normalize_relpath,
    protected_patterns,
    safe_rel_glob,
    safe_relpath,
)

CORPUS = Path(__file__).parent / "corpus"


@pytest.fixture
def root(tmp_path: Path) -> Path:
    """A workspace with a source tree, a `.pm/` directory and hostile symlinks."""
    workspace = tmp_path / "ws"
    (workspace / "src").mkdir(parents=True)
    (workspace / "src" / "app.py").write_text("x = 1\n", encoding="utf-8")
    (workspace / ".pm").mkdir()
    outside = tmp_path / "outside"
    outside.mkdir()
    (workspace / "link_out").symlink_to(outside)
    (workspace / "link_root").symlink_to(workspace)
    (workspace / "src" / "pm").symlink_to(Path("..") / ".pm")
    (workspace / "inside").symlink_to(Path("src"))
    return workspace


# ---------------------------------------------------------------- safe_relpath: accepted


@pytest.mark.parametrize(
    ("given", "expected"),
    [
        ("src/app.py", "src/app.py"),
        ("./src//app.py", "src/app.py"),
        ("src/./new_file.py", "src/new_file.py"),
        ("pages/[id].tsx", "pages/[id].tsx"),
        ("docs/My File.txt", "docs/My File.txt"),
        ("tests", "tests"),
        ("src/-dash-inside.py", "src/-dash-inside.py"),
        ("src/environment.py", "src/environment.py"),
    ],
)
def test_safe_relpath_accepts_and_normalizes(root: Path, given: str, expected: str) -> None:
    assert safe_relpath(root, given) == expected


def test_safe_relpath_follows_a_symlink_that_stays_inside(root: Path) -> None:
    assert safe_relpath(root, "inside/app.py") == "inside/app.py"


# ---------------------------------------------------------------- safe_relpath: rejected


@pytest.mark.parametrize(
    ("given", "reason"),
    [
        ("", "empty"),
        ("x" * 513, "longer than 512"),
        ("/".join(["a"] * 65), "more than 64 components"),
        ("/etc/passwd", "absolute"),
        ("~/.ssh/id_rsa", "home-relative"),
        ("../x", "'..'"),
        ("src/../../x", "'..'"),
        ("-rf", "starts with '-'"),
        ("./--config=evil", "starts with '-'"),
        ("a\\b", "backslash"),
        ("C:/x", "colon"),
        ("a\x00b", "control"),
        ("a\nb", "control"),
        ("a\tb", "control"),
        ("a\u200bb", "format"),
        ("a\u202eb", "format"),
        ("a\U000e0061b", "format"),
        ("a\u00a0b", "unusual space"),
        ("a\u2028b", "control, format or unusual space"),
        (".", "workspace root"),
        ("./", "workspace root"),
        ("*", "wildcard"),
        ("src/a?.py", "wildcard"),
        (".pm/tasks.yaml", "protected"),
        (".pm", "protected"),
        (".PM/tasks.yaml", "protected"),
        (".git/config", "protected"),
        (".git./config", "protected"),
        (".git /hooks/pre-commit", "protected"),
        ("vendor/.git/hooks/pre-commit", "protected"),
        (".github/workflows/ci.yml", "protected"),
        ("AGENTS.md", "protected"),
        ("claude.md", "protected"),
        ("docs/AGENTS.md", "protected"),
        (".claude/settings.json", "protected"),
        (".mcp.json", "protected"),
        (".env", "protected"),
        ("app/.env.local", "protected"),
        ("link_out/secret", "outside the workspace"),
        ("link_out", "outside the workspace"),
        ("link_root", "workspace root"),
        ("src/pm/tasks.yaml", "resolves to a protected path"),
        ("link_root/.pm/tasks.yaml", "protected path"),
    ],
)
def test_safe_relpath_rejects(root: Path, given: str, reason: str) -> None:
    with pytest.raises(PolicyViolation, match=reason) as info:
        safe_relpath(root, given)
    assert info.value.exit_code is ExitCode.SECURITY_VIOLATION


def test_safe_relpath_rejects_non_strings(root: Path) -> None:
    with pytest.raises(PolicyViolation, match="must be a string"):
        safe_relpath(root, 123)  # type: ignore[arg-type]


def test_rejection_message_is_shortened(root: Path) -> None:
    with pytest.raises(PolicyViolation) as info:
        safe_relpath(root, "x" * 600)
    assert "…" in info.value.message
    assert len(info.value.message) < 200


def test_safe_relpath_extra_protected(root: Path) -> None:
    with pytest.raises(PolicyViolation, match="protected"):
        safe_relpath(root, "deploy/prod.tf", extra_protected=["deploy/**"])
    assert safe_relpath(root, "src/app.py", extra_protected=["deploy/**"]) == "src/app.py"


def test_safe_relpath_works_when_root_is_a_symlink(root: Path, tmp_path: Path) -> None:
    alias = tmp_path / "alias"
    alias.symlink_to(root)
    assert safe_relpath(alias, "src/app.py") == "src/app.py"
    with pytest.raises(PolicyViolation, match="outside"):
        safe_relpath(alias, "link_out/x")


# ---------------------------------------------------------------- safe_rel_glob


@pytest.mark.parametrize(
    ("given", "expected"),
    [
        ("src/**", "src/**"),
        ("src/app/**/*.py", "src/app/**/*.py"),
        ("./tests//test_*.py", "tests/test_*.py"),
        ("docs/*.md", "docs/*.md"),
        ("src/?.py", "src/?.py"),
        ("pages/[id].tsx", "pages/[id].tsx"),
        ("migrations/**", "migrations/**"),
        ("pyproject.toml", "pyproject.toml"),
    ],
)
def test_safe_rel_glob_accepts(given: str, expected: str) -> None:
    assert safe_rel_glob(given) == expected


@pytest.mark.parametrize(
    ("given", "reason"),
    [
        ("**", "could match"),
        ("*", "could match"),
        ("*.md", "could match the protected path 'AGENTS.md'"),
        (".*/**", "could match"),
        (".p?/tasks.yaml", "could match the protected path '.pm/\\*\\*'"),
        ("*/config", "could match"),
        (".github/**", "could match"),
        (".claude/agents/*.md", "could match"),
        (".Git/**", "could match"),
        (".env*", "could match"),
        ("src/**/.env", "names a protected path"),
        ("src/**/.env*", "names a protected path"),
        ("src/**/.git/**", "names a protected path"),
        ("a/**b", "whole component"),
        ("**x/y", "whole component"),
        ("/".join(["a", "**"] * 5), "more than 4"),
        ("../x/**", "'..'"),
        ("/abs/**", "absolute"),
        ("-x/**", "starts with '-'"),
        ("src/\u200b**", "format"),
    ],
)
def test_safe_rel_glob_rejects(given: str, reason: str) -> None:
    with pytest.raises(PolicyViolation, match=reason):
        safe_rel_glob(given)


def test_safe_rel_glob_extra_protected() -> None:
    with pytest.raises(PolicyViolation, match="secrets"):
        safe_rel_glob("secrets/*", extra_protected=["secrets/**"])
    with pytest.raises(PolicyViolation, match="could match"):
        safe_rel_glob("src/*", extra_protected=["src/*"])
    assert safe_rel_glob("src/**", extra_protected=["secrets/**"]) == "src/**"


def test_corpus_c009_every_entry_is_rejected() -> None:
    case = YAML(typ="safe", pure=True).load(
        (CORPUS / "C-009-path-escape.yaml").read_text(encoding="utf-8")
    )
    entries = [line for line in case["input"]["text"].splitlines() if line]
    assert len(entries) == 5
    for entry in entries:
        with pytest.raises(PolicyViolation):
            safe_rel_glob(entry)


# ---------------------------------------------------------------- protected patterns


def test_protected_paths_match_security_section_9_2() -> None:
    assert set(PROTECTED_PATHS) == {
        ".pm/**", ".git/**", ".github/**", ".gitlab-ci.yml",
        "AGENTS.md", "CLAUDE.md", "GEMINI.md", ".claude/**",
        ".gemini/**", ".codex/**", ".agents/**", ".mcp.json",
        ".gitattributes", ".gitmodules", ".aipmignore", "**/.env*",
    }  # fmt: skip


def test_normalize_relpath_checks_syntax_only() -> None:
    assert normalize_relpath("./docs//idea.md") == "docs/idea.md"
    assert normalize_relpath("AGENTS.md") == "AGENTS.md"  # metadata: protection is not checked
    with pytest.raises(PolicyViolation, match=r"'\.\.'"):
        normalize_relpath("../idea.md")


def test_protected_patterns_adds_validated_extras() -> None:
    assert protected_patterns(["./deploy//**"]) == (*PROTECTED_PATHS, "deploy/**")
    with pytest.raises(PolicyViolation, match=r"'\.\.'"):
        protected_patterns(["../elsewhere/**"])


@pytest.mark.parametrize(
    ("path", "patterns", "expected"),
    [
        ("src/app.py", PROTECTED_PATHS, False),
        ("README.md", PROTECTED_PATHS, False),
        (".pm", PROTECTED_PATHS, True),
        ("a/b/.env.production", PROTECTED_PATHS, True),
        ("sub/.github/x", PROTECTED_PATHS, True),
        ("x/y", ("x*y",), False),
        ("xay", ("x*y",), True),
        ("x/y", ("x?y",), False),
        ("x/a/b/y", ("x/**/y",), True),
        ("x/y", ("x/**/y",), True),
        ("q/x/y", ("**",), True),
        ("a" * 300 + "/" + "b" * 200, ("a*/**/b*",), True),
    ],
)
def test_is_protected(path: str, patterns: tuple[str, ...], expected: bool) -> None:
    assert is_protected(path, patterns) is expected


def test_symlink_fixture_is_what_the_tests_assume(root: Path) -> None:
    assert (root / "link_out").is_symlink()
    assert os.path.realpath(root / "src" / "pm") == os.path.realpath(root / ".pm")
