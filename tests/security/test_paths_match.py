"""`glob_may_match` (build prompt 04): which owned globs may hold test or config files (G3)."""

import pytest

from aipm.security.paths import glob_may_match


@pytest.mark.parametrize(
    ("glob", "pattern", "expected"),
    [
        ("tests/test_app.py", "test_*.py", True),
        ("src/**", "conftest.py", True),
        ("src/**", "**/conftest.py", True),
        ("app/*", "conftest.py", True),
        ("src/t*.py", "test_*.py", True),
        ("src/c*.py", "conftest.py", True),
        ("src/*.md", "test_*.py", False),
        ("src/app.py", "test_*.py", False),
        ("SRC/Conftest.PY", "conftest.py", True),
        ("pyproject.toml", "pyproject.toml", True),
        ("docs/pyproject.toml", "pyproject.toml", True),
        ("src/x.ts", "*.test.*", False),
        ("src/*.ts", "*.test.*", True),
        ("ci/**", ".github/**", True),
        ("src/a.py", ".github/**", False),
    ],
)
def test_glob_may_match(glob: str, pattern: str, expected: bool) -> None:
    assert glob_may_match(glob, pattern) is expected
