"""Deterministic YAML 1.2 with ruamel.yaml; other versions, aliases, anchors, tags, collections
as mapping keys, integers longer than 100 characters and files over 1 MiB rejected.

Loading scans the event stream before constructing anything, so an alias bomb is refused
before it can expand. Dumping keeps keys in the order given (schema order), writes scalar-only
lists and mappings in flow style (`run: [uv, sync, --frozen]`), folds long strings near 100
columns where they have single spaces to break at, writes multi-line strings as literal blocks
and `None` as `null`, and ends with a newline. Error messages carry the position and the
parser's problem, never the input text.
"""

import io
import re
from collections.abc import Iterable
from typing import Any

from ruamel.yaml import YAML
from ruamel.yaml.comments import CommentedMap
from ruamel.yaml.error import MarkedYAMLError, YAMLError
from ruamel.yaml.events import (
    AliasEvent,
    CollectionEndEvent,
    CollectionStartEvent,
    DocumentStartEvent,
    Event,
    MappingStartEvent,
    NodeEvent,
    ScalarEvent,
)
from ruamel.yaml.representer import RoundTripRepresenter

from aipm.domain.errors import SchemaError

MAX_YAML_BYTES = 1_048_576
MAX_DEPTH = 64
MAX_NUMBER_CHARS = 100
LINE_WIDTH = 100


_QUOTED = re.compile(r"\"[^\"\n]*\"|'[^'\n]*'")
# A plain scalar that YAML resolves to an integer. Hex, octal and binary ones of any length
# construct, but Python cannot print an integer of more than 4,300 digits.
_INTEGER = re.compile(r"[-+]?(?:0x[0-9a-fA-F_]+|0o[0-7_]+|0b[01_]+|[0-9][0-9_]*)")


def _problem(text: object) -> str:
    """The parser's problem, with quoted input (keys, values, tokens) masked out."""
    problem = str(text or "")
    if "duplicate key" in problem:
        return "found a duplicate key"
    return _QUOTED.sub(lambda m: m.group(0) if len(m.group(0)) <= 6 else "'…'", problem)[:200]


def _where(exc: YAMLError) -> str:
    marked: Any = exc  # ruamel.yaml has no type hints
    if isinstance(exc, MarkedYAMLError) and marked.problem_mark is not None:
        mark = marked.problem_mark
        return f"line {mark.line + 1}, column {mark.column + 1}: {_problem(marked.problem)}"
    return type(exc).__name__


def _check_events(events: Iterable[Event], source: str) -> None:
    # One entry per open collection: None for a sequence; for a mapping, whether the next node
    # is a key. A collection as a key cannot be constructed (`? - a: 1`) or becomes a tuple.
    open_collections: list[bool | None] = []
    for event in events:
        node: Any = event
        if isinstance(event, AliasEvent):
            raise SchemaError(f"{source}: YAML aliases are not allowed")
        # `%YAML 1.1` turns on base-60 integers (`1:59:59`) and `yes`/`off` booleans.
        if isinstance(event, DocumentStartEvent) and node.version not in (None, (1, 2)):
            raise SchemaError(f"{source}: only YAML 1.2 is read")
        if isinstance(event, NodeEvent) and node.anchor is not None:
            raise SchemaError(f"{source}: YAML anchors are not allowed")
        if isinstance(event, NodeEvent) and getattr(node, "tag", None) is not None:
            raise SchemaError(f"{source}: YAML tags are not allowed")
        if (
            isinstance(event, ScalarEvent)
            and node.style is None
            and len(node.value) > MAX_NUMBER_CHARS
            and _INTEGER.fullmatch(node.value)
        ):
            raise SchemaError(f"{source}: a YAML number longer than {MAX_NUMBER_CHARS} characters")
        if isinstance(event, NodeEvent) and open_collections and open_collections[-1] is not None:
            if open_collections[-1] and isinstance(event, CollectionStartEvent):
                raise SchemaError(f"{source}: YAML mapping keys must be scalars")
            open_collections[-1] = not open_collections[-1]
        if isinstance(event, CollectionStartEvent):
            open_collections.append(True if isinstance(event, MappingStartEvent) else None)
            if len(open_collections) > MAX_DEPTH:
                raise SchemaError(f"{source}: YAML nested deeper than {MAX_DEPTH} levels")
        elif isinstance(event, CollectionEndEvent):
            open_collections.pop()


def load_yaml(text: str, *, source: str = "YAML") -> object:
    """Parse YAML safely (ARCHITECTURE §6.2), or raise `SchemaError` (exit 2).

    A value out of range, such as the date `2026-13-45` or an integer too long for Python,
    parses, then fails to construct with `ValueError`; it is invalid YAML like any other
    (red-team v0.1, RT01-7).
    """
    if len(text.encode("utf-8", errors="surrogatepass")) > MAX_YAML_BYTES:
        raise SchemaError(f"{source} is larger than 1 MiB")
    parser: Any = YAML(typ="safe", pure=True)
    try:
        _check_events(parser.parse(text), source)
        return parser.load(text)
    except YAMLError as exc:
        raise SchemaError(f"{source}: not valid YAML ({_where(exc)})") from None
    except ValueError:
        raise SchemaError(f"{source}: not valid YAML (a value out of range)") from None
    except AssertionError:  # ruamel.yaml asserts on a `%YAML 1.3` directive
        raise SchemaError(f"{source}: only YAML 1.2 is read") from None


class _Representer(RoundTripRepresenter):
    """Round-trip representer (keeps key order) with aipm's scalar styles, set per instance."""


def _represent_str(representer: Any, data: str) -> object:
    style = "|" if "\n" in data else None
    return representer.represent_scalar("tag:yaml.org,2002:str", data, style=style)


def _represent_none(representer: Any, data: None) -> object:
    return representer.represent_scalar("tag:yaml.org,2002:null", "null")


_representers: Any = _Representer
_representers.add_representer(str, _represent_str)
_representers.add_representer(type(None), _represent_none)


def dump_yaml(data: object) -> str:
    """Dump YAML in the given key order with a trailing newline. Identical data, identical bytes."""
    yaml: Any = YAML(typ="rt", pure=True)
    yaml.Representer = _Representer
    yaml.width = LINE_WIDTH
    yaml.indent(mapping=2, sequence=4, offset=2)
    yaml.allow_unicode = True
    yaml.default_flow_style = None  # scalar-only lists and maps in flow style: [uv, run, ...]
    if isinstance(data, dict):
        root: Any = CommentedMap(data)  # pyright: ignore[reportUnknownArgumentType]
        root.fa.set_block_style()  # the document itself is always block style
        data = root
    out = io.StringIO()
    yaml.dump(data, out)
    return out.getvalue()
