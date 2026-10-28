"""No tracked text file hides characters a reviewer cannot see ("Trojan Source").

Bidirectional overrides, zero-width characters, Unicode Tags and raw control characters can
make code or instructions read differently from what runs. Tests and corpus cases write them
as escapes instead.
"""

import unicodedata
from pathlib import Path

from tests.conftest import REPO_ROOT

SCANNED = [
    "src",
    "tests",
    "docs",
    "examples",
    ".github",
    ".claude",
    ".githooks",
    "AGENTS.md",
    "CLAUDE.md",
    "README.md",
    "SECURITY.md",
    "CONTRIBUTING.md",
    "CODE_OF_CONDUCT.md",
    "CHANGELOG.md",
    "pyproject.toml",
]
TEXT_SUFFIXES = {".py", ".md", ".yaml", ".yml", ".toml", ".j2", ".json", ".txt", ""}


def hidden_characters(text: str) -> list[str]:
    return sorted(
        {
            f"U+{ord(ch):04X}"
            for ch in text
            if ch not in "\n\t"
            and (unicodedata.category(ch) in {"Cc", "Cf"} or 0xE0000 <= ord(ch) <= 0xE007F)
        }
    )


def text_files() -> list[Path]:
    files: list[Path] = []
    for entry in SCANNED:
        path = REPO_ROOT / entry
        if path.is_file():
            files.append(path)
        elif path.is_dir():
            files.extend(
                p
                for p in path.rglob("*")
                if p.is_file() and p.suffix in TEXT_SUFFIXES and "__pycache__" not in p.parts
            )
    return sorted(files)


def test_no_hidden_characters_in_tracked_text() -> None:
    offenders = {}
    for path in text_files():
        try:
            text = path.read_text(encoding="utf-8")
        except UnicodeDecodeError:
            continue
        if found := hidden_characters(text):
            offenders[str(path.relative_to(REPO_ROOT))] = found
    assert offenders == {}


def test_detector_finds_each_kind() -> None:
    samples = [chr(0x202E), chr(0x200B), chr(0xE0061), chr(0x1B), chr(0x9B)]
    for sample in samples:
        assert hidden_characters(f"a{sample}b") == [f"U+{ord(sample):04X}"]
