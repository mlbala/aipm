"""Model replies nested too deeply are refused before parsing, on every Python (prompt 04).

Python 3.14's JSON decoder no longer raises RecursionError at depths that 3.12 and 3.13 did,
so the limit is an explicit bracket count, not the interpreter's recursion limit.
"""

import pytest
from pydantic import BaseModel

from aipm.llm.structured import MAX_JSON_DEPTH, OutputInvalid, parse_response


class Loose(BaseModel):
    a: object = None


def nested(depth: int) -> str:
    """An object whose `a` holds arrays, `depth` levels in total."""
    inner = depth - 1
    return '{"a": ' + "[" * inner + "]" * inner + "}"


@pytest.mark.parametrize(
    "raw",
    [
        "[" * 100_000 + "]" * 100_000,
        nested(100_000),
        nested(MAX_JSON_DEPTH + 1),
        '{"a": ' + "{" * 70 + "}" * 70 + "}",
    ],
)
def test_too_deep_is_refused(raw: str) -> None:
    with pytest.raises(OutputInvalid) as info:
        parse_response(raw, Loose)
    assert info.value.problems == ["the reply is nested too deeply"]


def test_the_limit_itself_is_allowed() -> None:
    assert parse_response(nested(MAX_JSON_DEPTH), Loose).a is not None


def test_brackets_inside_strings_do_not_count() -> None:
    text = '{"a": "' + "[" * 1000 + '\\"' + "{" * 1000 + '"}'
    assert parse_response(text, Loose).a == "[" * 1000 + '"' + "{" * 1000
