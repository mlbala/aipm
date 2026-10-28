"""The injection corpus is well-formed (tests/security/corpus/README.md).

The cases are fed through aipm's input paths by the build prompts that add those paths.
"""

import unicodedata
from pathlib import Path

import pytest
from ruamel.yaml import YAML

from aipm.domain.errors import ExitCode

CORPUS = Path(__file__).parent / "corpus"
CASES = sorted(CORPUS.glob("C-*.yaml"))
VECTORS = {
    "direct-instruction",
    "indirect-instruction",
    "smuggling",
    "boundary",
    "exfiltration",
    "structural",
    "path",
    "terminal",
    "config-redirection",
}


def load(path: Path) -> dict[str, object]:
    data = YAML(typ="safe", pure=True).load(path.read_text(encoding="utf-8"))
    assert isinstance(data, dict)
    return data


def test_corpus_has_the_first_ten_cases() -> None:
    assert [p.name.split("-", 2)[1] for p in CASES][:10] == [f"{n:03d}" for n in range(1, 11)]


@pytest.mark.parametrize("path", CASES, ids=lambda p: p.stem)
def test_case_format(path: Path) -> None:
    case = load(path)
    assert set(case) == {"id", "vector", "input", "expected"}
    assert path.name.startswith(f"{case['id']}-")
    assert case["vector"] in VECTORS

    inp = case["input"]
    assert isinstance(inp, dict)
    assert set(inp) == {"surface", "text"}
    assert isinstance(inp["surface"], str)
    assert isinstance(inp["text"], str)
    assert inp["text"]

    expected = case["expected"]
    assert isinstance(expected, dict)
    assert set(expected) <= {"outcome", "exit_code"}
    assert isinstance(expected["outcome"], str)
    assert expected["outcome"]
    if "exit_code" in expected:
        assert expected["exit_code"] in {int(code) for code in ExitCode}


@pytest.mark.parametrize("path", CASES, ids=lambda p: p.stem)
def test_files_hold_no_raw_hostile_characters(path: Path) -> None:
    """Hostile characters must be written as YAML escapes, not raw (README)."""
    raw = path.read_text(encoding="utf-8")
    bad = [
        f"U+{ord(ch):04X}"
        for ch in raw
        if ch != "\n" and (unicodedata.category(ch) in {"Cc", "Cf"} or ord(ch) >= 0xE0000)
    ]
    assert bad == []


def test_ids_are_unique() -> None:
    ids = [load(p)["id"] for p in CASES]
    assert len(ids) == len(set(ids))


@pytest.mark.parametrize(
    ("case_id", "needle"),
    [
        ("C-004", "\U000e0061"),  # Unicode Tag "a"
        ("C-005", "\u200b"),  # zero-width space
        ("C-010", "\x1b]52;"),  # OSC 52
    ],
)
def test_escapes_decode_to_the_hostile_characters(case_id: str, needle: str) -> None:
    (path,) = CORPUS.glob(f"{case_id}-*.yaml")
    text = load(path)["input"]
    assert isinstance(text, dict)
    assert needle in text["text"]
