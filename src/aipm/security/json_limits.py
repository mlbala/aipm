"""JSON nested deeper than a fixed limit is unreadable, on every Python (red-team v0.4, RT04-21).

Up to Python 3.13, `json.loads` raised `RecursionError` on JSON nested a few thousand deep, and
the readers of agent output and of files a repository controls relied on that (RT04-1, RT04-10).
Python 3.14 parses JSON nested 100,000 deep, so the same input became data. `loads_bounded`
counts the nesting before it parses and refuses anything deeper than a fixed limit, so the result
no longer depends on the interpreter. Pure: no I/O.
"""

import json
import re
from typing import Any

MAX_DEPTH = 256
"""Agent events, settings files, registry answers and test reports nest far less than this."""

_TOKEN = re.compile(r'"(?:[^"\\]++|\\.)*+(?:"|\\?\Z)|[\[\]{}]', re.DOTALL)
"""A string (to skip), or one bracket. An unterminated string runs to the end."""


class TooDeep(ValueError):
    """JSON nested deeper than the limit. A `ValueError`, like any other unreadable JSON."""


def depth(text: str, *, stop_above: int | None = None) -> int:
    """The deepest nesting of arrays and objects, counting brackets outside strings. With
    `stop_above`, the scan ends as soon as the nesting passes it."""
    deepest = level = 0
    for match in _TOKEN.finditer(text):
        piece = match.group()
        if piece[0] == '"':
            continue
        level += 1 if piece in "[{" else -1
        if level > deepest:
            deepest = level
            if stop_above is not None and deepest > stop_above:
                break
    return deepest


def loads_bounded(data: str | bytes, *, max_depth: int = MAX_DEPTH, **kwargs: Any) -> Any:
    """`json.loads(data, **kwargs)`, or `TooDeep` when `data` nests deeper than `max_depth`.

    Bytes are decoded exactly as `json.loads` decodes them (UTF-8, -16 or -32, with
    `surrogatepass`); undecodable bytes raise `UnicodeDecodeError`, a `ValueError`. Callers catch
    `ValueError` for every unreadable input. Fewer brackets than the limit skip the scan.
    """
    if isinstance(data, bytes):
        text = data.decode(json.detect_encoding(data), "surrogatepass")
    else:
        text = data
    brackets = text.count("[") + text.count("{")
    if brackets > max_depth and depth(text, stop_above=max_depth) > max_depth:
        raise TooDeep(f"nested deeper than {max_depth} levels")
    try:
        return json.loads(text, **kwargs)
    except RecursionError:  # an interpreter whose limit is lower still: the same answer
        raise TooDeep(f"nested deeper than {max_depth} levels") from None
