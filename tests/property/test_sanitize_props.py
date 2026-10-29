"""Property tests for L1 hygiene (§20): idempotent, and removed classes never survive."""

import re
import unicodedata

from hypothesis import given, settings
from hypothesis import strategies as st

from aipm.security.sanitize import (
    has_mention,
    sanitize_for_context,
    sanitize_text,
    strip_terminal_escapes,
)

# Characters the sanitizer must never let through, plus pieces of escape sequences.
HOSTILE = st.sampled_from(
    [
        "\x00", "\x07", "\x08", "\r", "\x1b", "\x7f", "\x85", "\x9b", "\x9c", "\x9d",
        "\u200b", "\u200d", "\u200e", "\u2060", "\ufeff", "\u202e", "\u2066", "\u061c",
        "\ufe0f", "\ufe0e", "\ufe00", "\U000e0041", "\U000e0100", "\u00ad", "\ud800",
        "[", "]", "\\", ";", "m", "P", "_", "^", "X", "0", "<!--", "-->", "\u0301", "e",
        "\u2764", "1", "\u20e3", "https://", "www.", "evil.example", " ",
    ]
)  # fmt: skip
TEXT = st.lists(st.one_of(HOSTILE, st.text(max_size=5)), max_size=40).map("".join)


def is_removed_class(ch: str, previous: str | None) -> bool:
    """Characters `sanitize_text` must never output (SECURITY.md §7.1)."""
    cp = ord(ch)
    if ch in "\n\t":
        return False
    if unicodedata.category(ch) in {"Cc", "Cf", "Cs"}:
        return True
    if 0xE0000 <= cp <= 0xE007F or 0xE0100 <= cp <= 0xE01EF or 0xFE00 <= cp <= 0xFE0D:
        return True
    if cp in (0xFE0E, 0xFE0F):
        return previous is None or previous in "\ufe0e\ufe0f"
    return False


@settings(max_examples=500)
@given(TEXT)
def test_sanitize_text_is_idempotent(text: str) -> None:
    once = sanitize_text(text, source="prop").text
    assert sanitize_text(once, source="prop").text == once


@settings(max_examples=500)
@given(TEXT)
def test_sanitize_text_never_outputs_a_removed_class(text: str) -> None:
    out = sanitize_text(text, source="prop").text
    previous: str | None = None
    for ch in out:
        assert not is_removed_class(ch, previous), f"U+{ord(ch):04X} survived"
        previous = ch
    assert unicodedata.is_normalized("NFC", out)


@settings(max_examples=300)
@given(TEXT)
def test_strip_terminal_escapes_leaves_no_escape_introducer(text: str) -> None:
    out = strip_terminal_escapes(text)
    assert "\x1b" not in out
    assert not any(0x80 <= ord(ch) <= 0x9F for ch in out)


@settings(max_examples=300)
@given(TEXT)
def test_sanitize_for_context_is_idempotent_and_leaves_no_comment_or_foreign_url(
    text: str,
) -> None:
    once = sanitize_for_context(text, allowed_url_domains=()).text
    assert sanitize_for_context(once, allowed_url_domains=()).text == once
    assert "<!--" not in once
    assert "https://" not in once
    assert "www." not in once.lower()


MENTION_TEXT = st.lists(
    st.one_of(
        HOSTILE, st.sampled_from(["@", "@.env", "@@", "\n", "\t", "x@y"]), st.text(max_size=5)
    ),
    max_size=40,
).map("".join)


@settings(max_examples=300)
@given(MENTION_TEXT)
def test_sanitize_for_context_leaves_no_at_mention(text: str) -> None:
    once = sanitize_for_context(text, allowed_url_domains=()).text
    assert not has_mention(once)
    assert not re.search(r"(?:^|\s)@\S", once)
