"""Managed blocks (ARCHITECTURE §10.2): aipm replaces only the text between its markers.

Content outside the markers is the user's and must never change, byte for byte. Malformed or
duplicate markers are refused (exit 2) so aipm never guesses which part of a file it owns.
"""

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st

from aipm.context.managed_block import (
    BEGIN,
    END,
    MalformedBlock,
    extract_block,
    find_block,
    replace_block,
)
from aipm.domain.errors import ExitCode, PolicyViolation

BLOCK = "# Generated\n\n- rule one\n"
NEW = "# Generated again\n"


def doc(prefix: str, old: str, suffix: str, *, newline: str = "\n") -> str:
    return f"{prefix}{BEGIN}{newline}{old}{END}{suffix}"


# ---------------------------------------------------------------- unit cases


def test_no_markers_appends_after_a_blank_line() -> None:
    out = replace_block("# My notes\n", BLOCK)
    assert out == f"# My notes\n\n{BEGIN}\n{BLOCK}{END}\n"
    assert extract_block(out) == BLOCK


def test_no_trailing_newline_gets_one_before_the_block() -> None:
    assert replace_block("notes", BLOCK) == f"notes\n\n{BEGIN}\n{BLOCK}{END}\n"


def test_an_empty_file_gets_only_the_block() -> None:
    assert replace_block("", BLOCK) == f"{BEGIN}\n{BLOCK}{END}\n"


def test_replace_keeps_both_sides_byte_for_byte() -> None:
    prefix, suffix = "# Mine\r\nkeep  \n\n", "  \n\nafter\ttabs é\n"
    out = replace_block(doc(prefix, "old\n", suffix), NEW)
    assert out == doc(prefix, NEW, suffix)


def test_an_altered_begin_marker_comment_is_normalised() -> None:
    out = replace_block(f"x\n<!-- aipm:begin edited by hand -->\nold\n{END}\n", NEW)
    assert out == f"x\n{BEGIN}\n{NEW}{END}\n"


def test_crlf_files_keep_crlf_inside_the_block() -> None:
    original = f"a\r\n{BEGIN}\r\nold\r\n{END}\r\nz\r\n"
    out = replace_block(original, "one\ntwo\n")
    assert out == f"a\r\n{BEGIN}\r\none\r\ntwo\r\n{END}\r\nz\r\n"
    assert extract_block(out) == "one\ntwo\n"
    assert replace_block("a\r\nb\r\n", "x\n").endswith(f"\r\n{BEGIN}\r\nx\r\n{END}\r\n")


def test_replacing_twice_is_the_same_as_once() -> None:
    once = replace_block("notes\n", BLOCK)
    assert replace_block(once, BLOCK) == once


def test_a_block_without_final_newline_gets_one() -> None:
    assert extract_block(replace_block("", "x")) == "x\n"


def test_an_empty_block() -> None:
    out = replace_block("", "")
    assert out == f"{BEGIN}\n{END}\n"
    assert extract_block(out) == ""


@pytest.mark.parametrize(
    "document",
    [
        f"{BEGIN}\nx\n",  # begin only
        f"x\n{END}\n",  # end only
        f"{BEGIN}\n{BEGIN}\nx\n{END}\n",  # two begins
        f"{BEGIN}\nx\n{END}\n{BEGIN}\ny\n{END}\n",  # two blocks
        f"{END}\nx\n{BEGIN}\n",  # wrong order
        f"text {BEGIN}\nx\n{END}\n",  # begin not on its own line
        f"{BEGIN}\nx\nmore {END}\n",  # end not on its own line
        f"{BEGIN} trailing\nx\n{END}\n",  # text after the begin marker
        f"{BEGIN}\nx\n{END} trailing\n",  # text after the end marker
        f"<!--aipm:BEGIN-->\nx\n{END}\n",  # near miss: spacing and case
        f"{BEGIN}\nx\n<!-- AIPM:END -->\n",  # near miss
        "<!-- aipm:begin --> <!-- aipm:end -->\n",  # both on one line
        "<!-- aipm:begin -->",  # begin at the end of the file
        f"<!-- aipm:begin --> x -->\nold\n{END}\n",  # a second comment end on the line
    ],
)
def test_malformed_markers_are_refused(document: str) -> None:
    with pytest.raises(MalformedBlock) as info:
        replace_block(document, BLOCK, name="AGENTS.md")
    assert info.value.exit_code is ExitCode.USAGE
    assert "AGENTS.md" in info.value.message
    assert info.value.hint


def test_an_html_comment_in_generated_content_is_refused() -> None:
    with pytest.raises(PolicyViolation):
        replace_block("", "x <!-- y -->\n")
    with pytest.raises(PolicyViolation):
        replace_block("", "x\ry\n")


def test_an_arrow_in_generated_content_is_fine() -> None:
    assert extract_block(replace_block("", "api --> db\n")) == "api --> db\n"


def test_find_block_reports_the_span() -> None:
    document = doc("pre\n", "old\n", "\npost\n")
    span = find_block(document)
    assert span is not None
    assert document[: span.begin] == "pre\n"
    assert document[span.content_start : span.content_end] == "old\n"
    assert document[span.end :] == "\npost\n"
    assert find_block("plain text") is None


# ---------------------------------------------------------------- properties

# Text that never contains an aipm marker or the start of an HTML comment.
USER_TEXT = st.text(alphabet=st.characters(blacklist_categories=("Cs",)), max_size=200).filter(
    lambda t: "<!--" not in t
)
BLOCK_TEXT = st.text(
    alphabet=st.characters(blacklist_categories=("Cs",), blacklist_characters="\r"),
    max_size=200,
).filter(lambda t: "<!--" not in t)


@settings(max_examples=300)
@given(USER_TEXT, BLOCK_TEXT)
def test_appending_keeps_the_user_text_as_a_prefix(user: str, block: str) -> None:
    out = replace_block(user, block)
    assert out.startswith(user)
    expected = block if not block or block.endswith("\n") else block + "\n"
    assert extract_block(out) == expected
    assert replace_block(out, block) == out


@settings(max_examples=300)
@given(USER_TEXT, USER_TEXT, BLOCK_TEXT, BLOCK_TEXT)
def test_replacing_never_touches_text_outside_the_markers(
    prefix: str, suffix: str, old: str, new: str
) -> None:
    head = prefix if not prefix or prefix.endswith("\n") else prefix + "\n"
    old_body = old if not old or old.endswith("\n") else old + "\n"
    tail = suffix if not suffix or suffix.startswith(("\n", "\r\n")) else "\n" + suffix
    original = doc(head, old_body, tail)
    out = replace_block(original, new)
    span = find_block(out)
    assert span is not None
    assert out[: span.begin] == head
    assert out[span.end :] == tail


FRAGMENTS = st.sampled_from(
    [BEGIN, END, "<!-- aipm:begin -->", "<!--", "-->", "aipm:end", "\n", "\r\n", "x", " ", "\t",
     "<!--AIPM:BEGIN-->", "é", "`"]
)  # fmt: skip


@settings(max_examples=500)
@given(st.lists(FRAGMENTS, max_size=12).map("".join), BLOCK_TEXT)
def test_fuzzed_markers_are_refused_or_handled_exactly(document: str, block: str) -> None:
    try:
        span = find_block(document)
        out = replace_block(document, block)
    except MalformedBlock:
        return
    if span is None:
        assert out.startswith(document)
    else:
        assert out[: span.begin] == document[: span.begin]
        assert out.endswith(document[span.end :])
    assert replace_block(out, block) == out
