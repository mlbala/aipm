"""Stable IDs: F-001, C-01, TM-01, T-001, AC-T001-1, Q-001, A-001, ADR-0001 (§6.2)."""

import re
from collections.abc import Iterable

ID_PATTERNS: dict[str, str] = {
    "feature": r"F-\d{3}",
    "nfr": r"NFR-\d{2}",
    "component": r"C-\d{2}",
    "threat": r"TM-\d{2}",
    "task": r"T-\d{3}",
    "acceptance": r"AC-T\d{3}-\d{1,2}",
    "question": r"Q-\d{3}",
    "assumption": r"A-\d{3}",
    "adr": r"ADR-\d{4}",
    "event": r"EV-[0-9a-f]{12}",
    "run": r"r-\d{8}-\d{4}-[0-9a-f]{4}",
}
"""Each kind's ID format, without anchors; `is_valid_id` matches the whole value."""

_COMPILED = {kind: re.compile(pattern) for kind, pattern in ID_PATTERNS.items()}


_SEQUENTIAL = {"question": ("Q-", 3), "assumption": ("A-", 3), "feature": ("F-", 3)}


def next_id(kind: str, used: Iterable[str]) -> str:
    """The next ID after the highest one in `used`: Q-001, A-001 or F-001 style."""
    if kind not in _SEQUENTIAL:
        raise ValueError(f"no sequential IDs for {kind!r}")
    prefix, width = _SEQUENTIAL[kind]
    highest = 0
    for value in used:
        if is_valid_id(kind, value):
            highest = max(highest, int(value[len(prefix) :]))
    if highest + 1 >= 10**width:
        raise ValueError(f"no {kind} IDs left")
    return f"{prefix}{highest + 1:0{width}d}"


def is_valid_id(kind: str, value: str) -> bool:
    """Return whether `value` is a well-formed ID of the given kind."""
    regex = _COMPILED.get(kind)
    if regex is None:
        raise ValueError(f"unknown ID kind {kind!r}")
    return regex.fullmatch(value) is not None
