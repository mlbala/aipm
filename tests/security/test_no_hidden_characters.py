"""No file in the repository hides characters a reviewer cannot see ("Trojan Source").

Bidirectional overrides, zero-width and other invisible characters, Unicode Tags, variation
selectors and raw control characters can make code or agent instructions (AGENTS.md, prompts)
read differently from what runs. Tests and corpus cases write them as escapes instead.

Every file git tracks, or would track, is checked. A file that is not valid UTF-8 fails,
unless it is binary (contains a NUL byte).
"""

import subprocess
import unicodedata
from pathlib import Path

from tests.conftest import REPO_ROOT

HIDDEN_CATEGORIES = {"Cc", "Cf", "Co", "Cs", "Cn", "Zl", "Zp"}
# Visible-looking blanks and fillers that are not in the categories above.
HIDDEN_CODEPOINTS = {0x115F, 0x1160, 0x2800, 0x3164, 0xFFA0}
ALLOWED_CONTROLS = {"\n", "\t"}


def is_hidden(ch: str) -> bool:
    if ch in ALLOWED_CONTROLS:
        return False
    code = ord(ch)
    return (
        unicodedata.category(ch) in HIDDEN_CATEGORIES
        or code in HIDDEN_CODEPOINTS
        or 0xFE00 <= code <= 0xFE0F  # variation selectors
        or 0xE0000 <= code <= 0xE0FFF  # tags and variation selectors supplement
    )


def hidden_characters(text: str) -> list[str]:
    return sorted({f"U+{ord(ch):04X}" for ch in text if is_hidden(ch)})


def repository_files() -> list[Path]:
    """Every tracked file, plus untracked files that are not ignored."""
    proc = subprocess.run(
        ["git", "ls-files", "-z", "--cached", "--others", "--exclude-standard"],
        cwd=REPO_ROOT,
        capture_output=True,
        check=True,
        timeout=60,
    )
    names = [n for n in proc.stdout.decode("utf-8").split("\0") if n]
    return sorted(REPO_ROOT / n for n in set(names) if (REPO_ROOT / n).is_file())


def test_every_file_is_scanned() -> None:
    files = {p.relative_to(REPO_ROOT).as_posix() for p in repository_files()}
    assert {"AGENTS.md", "pyproject.toml", ".gitleaks.toml", ".githooks/pre-push"} <= files


def test_no_hidden_characters_in_the_repository() -> None:
    offenders: dict[str, object] = {}
    for path in repository_files():
        data = path.read_bytes()
        if b"\0" in data:
            continue  # binary
        rel = path.relative_to(REPO_ROOT).as_posix()
        try:
            text = data.decode("utf-8")
        except UnicodeDecodeError as exc:
            offenders[rel] = f"not valid UTF-8: {exc}"
            continue
        if found := hidden_characters(text):
            offenders[rel] = found
    assert offenders == {}


def test_detector_finds_each_kind() -> None:
    samples = [
        0x202E,  # right-to-left override
        0x200B,  # zero-width space
        0xE0061,  # tag "a"
        0xFE0F,  # variation selector 16
        0xE0100,  # variation selector 17
        0xE000,  # private use
        0x2028,  # line separator
        0x3164,  # Hangul filler
        0x2800,  # braille blank
        0x1B,  # escape
        0x9B,  # C1 CSI
    ]
    for code in samples:
        assert hidden_characters(f"a{chr(code)}b") == [f"U+{code:04X}"]


def test_ordinary_text_passes() -> None:
    assert hidden_characters("Plain text, § sections, → arrows, café, 日本語.\n\tok") == []
