"""Deterministic YAML with ruamel.yaml; aliases, anchors, tags and files over 1 MiB rejected.

Loading scans the event stream before constructing anything, so an alias bomb is refused
before it can expand. Dumping keeps keys in the order given (schema order), folds long strings
near 100 columns where they have single spaces to break at, writes multi-line strings as literal
blocks and `None` as `null`, and ends with a newline. Error messages carry the position and the
parser's problem, never the input text.
"""

import io
from collections.abc import Iterable
from typing import Any

from ruamel.yaml import YAML
from ruamel.yaml.error import MarkedYAMLError, YAMLError
from ruamel.yaml.events import (
    AliasEvent,
    CollectionEndEvent,
    CollectionStartEvent,
    Event,
    NodeEvent,
)
from ruamel.yaml.representer import RoundTripRepresenter

from aipm.domain.errors import SchemaError

MAX_YAML_BYTES = 1_048_576
MAX_DEPTH = 64
LINE_WIDTH = 100


def _where(exc: YAMLError) -> str:
    marked: Any = exc  # ruamel.yaml has no type hints
    if isinstance(exc, MarkedYAMLError) and marked.problem_mark is not None:
        mark = marked.problem_mark
        return f"line {mark.line + 1}, column {mark.column + 1}: {marked.problem}"
    return type(exc).__name__


def _check_events(events: Iterable[Event], source: str) -> None:
    depth = 0
    for event in events:
        node: Any = event
        if isinstance(event, AliasEvent):
            raise SchemaError(f"{source}: YAML aliases are not allowed")
        if isinstance(event, NodeEvent) and node.anchor is not None:
            raise SchemaError(f"{source}: YAML anchors are not allowed")
        if isinstance(event, NodeEvent) and getattr(node, "tag", None) is not None:
            raise SchemaError(f"{source}: YAML tags are not allowed")
        if isinstance(event, CollectionStartEvent):
            depth += 1
            if depth > MAX_DEPTH:
                raise SchemaError(f"{source}: YAML nested deeper than {MAX_DEPTH} levels")
        elif isinstance(event, CollectionEndEvent):
            depth -= 1


def load_yaml(text: str, *, source: str = "YAML") -> object:
    """Parse YAML safely (ARCHITECTURE §6.2), or raise `SchemaError` (exit 2)."""
    if len(text.encode("utf-8", errors="surrogatepass")) > MAX_YAML_BYTES:
        raise SchemaError(f"{source} is larger than 1 MiB")
    parser: Any = YAML(typ="safe", pure=True)
    try:
        _check_events(parser.parse(text), source)
        return parser.load(text)
    except YAMLError as exc:
        raise SchemaError(f"{source}: not valid YAML ({_where(exc)})") from None


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
    out = io.StringIO()
    yaml.dump(data, out)
    return out.getvalue()
