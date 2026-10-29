"""Structured output: the wire schema sent to providers, and strict parsing of responses (§14).

One provider-neutral wire schema is derived from each role's Pydantic model: every property is
required, `additionalProperties` is false, and only the keywords both providers' strict modes
accept are kept. Length, size and pattern limits move into the description text, because the
providers do not enforce them; Pydantic enforces every one of them after parsing (ADR-0014).

Parsing is strict: one JSON object, no duplicate keys, no NaN or Infinity, a size cap, and
Pydantic strict mode against a model with `extra="forbid"`. Validation errors are turned into a
repair note that names fields and rules only, never the rejected text, and masks any key the
model invented, so the repair prompt carries nothing the model wrote.
"""

import json
import re
import unicodedata
from collections.abc import Iterable, Mapping
from typing import Any, get_args, get_origin

from pydantic import BaseModel, ValidationError

MAX_RESPONSE_CHARS = 524_288
MAX_JSON_DEPTH = 64
"""Arrays and objects nested deeper than this are refused before parsing: the check must not
depend on the interpreter's recursion limit, which Python 3.14 no longer hits at this depth."""
MAX_PROBLEMS = 10

_KEEP = ("type", "enum")  # docstring descriptions stay home; guidance is in the prompt
_LIMITS: Mapping[str, str] = {
    "minLength": "at least {} characters",
    "maxLength": "at most {} characters",
    "pattern": "must match the regular expression {}",
    "format": "format {}",
    "minItems": "at least {} items",
    "maxItems": "at most {} items",
    "uniqueItems": "items must be unique",
    "minimum": "at least {}",
    "maximum": "at most {}",
    "exclusiveMinimum": "more than {}",
    "exclusiveMaximum": "less than {}",
}
_REFUSED = ("patternProperties", "propertyNames", "dependentSchemas", "if", "not", "oneOf")
_FENCE = re.compile(r"\A```(?:json)?[ \t]*\n(?P<body>.*?)\n?```\Z", re.DOTALL)
_SAFE_NAME = re.compile(r"[A-Za-z_][A-Za-z0-9_]{0,63}")


class OutputInvalid(Exception):
    """The response did not parse or validate. `problems` is safe to send back to the model."""

    def __init__(self, problems: list[str]) -> None:
        super().__init__("; ".join(problems))
        self.problems = problems


# ---------------------------------------------------------------- the wire schema


def _notes(node: Mapping[str, Any]) -> list[str]:
    notes: list[str] = []
    for key, template in _LIMITS.items():
        if key in node and node[key] is not False:
            notes.append(template.format(node[key]))
    return notes


def _children(node: Mapping[str, Any], out: dict[str, Any]) -> None:
    """Convert the properties of an object or the items of an array."""
    kind = node.get("type")
    if kind == "object":
        extra = node.get("additionalProperties")
        if isinstance(extra, Mapping) or extra is True:
            raise ValueError("role schemas cannot use free-form mappings")
        properties: Mapping[str, Any] = node.get("properties", {})
        out["properties"] = {name: _convert(prop) for name, prop in properties.items()}
        out["required"] = list(properties)
        out["additionalProperties"] = False
    elif kind == "array":
        items: object = node.get("items")
        if not isinstance(items, Mapping):
            raise ValueError("role schema arrays need one item schema")
        out["items"] = _convert(items)  # pyright: ignore[reportUnknownArgumentType]


def _convert(node: Mapping[str, Any]) -> dict[str, Any]:
    for key in _REFUSED:
        if key in node:
            raise ValueError(f"role schemas cannot use {key}")
    if "$ref" in node:
        return {"$ref": node["$ref"]}
    if "allOf" in node:
        parts = node["allOf"]
        if len(parts) != 1:
            raise ValueError("role schemas cannot combine schemas with allOf")
        return _convert({**{k: v for k, v in node.items() if k != "allOf"}, **parts[0]})
    out: dict[str, Any] = {key: node[key] for key in _KEEP if key in node}
    if "anyOf" in node:
        out["anyOf"] = [_convert(variant) for variant in node["anyOf"]]
    if "const" in node:
        out["enum"] = [node["const"]]
    if notes := _notes(node):
        out["description"] = "; ".join(notes) + "."
    _children(node, out)
    if "type" not in out and "anyOf" not in out and "enum" not in out:
        raise ValueError("every role schema node needs a type")
    return out


def wire_schema(model: type[BaseModel]) -> dict[str, Any]:
    """The JSON schema sent to providers: all properties required, no extra properties."""
    raw = model.model_json_schema()
    definitions: Mapping[str, Any] = raw.get("$defs", {})
    root = _convert({k: v for k, v in raw.items() if k != "$defs"})
    if definitions:
        root["$defs"] = {name: _convert(node) for name, node in definitions.items()}
    return root


def schema_name(model: type[BaseModel]) -> str:
    """A schema name every provider accepts: letters, digits, `_` and `-`, at most 64."""
    name = re.sub(r"[^A-Za-z0-9_\-]", "_", model.__name__)[:64]
    return name or "response"


# ---------------------------------------------------------------- parsing


def _no_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("the JSON object has a duplicate key")
        result[key] = value
    return result


def _no_constants(name: str) -> Any:
    raise ValueError(f"{name} is not valid JSON")


def _clean(text: str, limit: int = 200) -> str:
    kept = "".join(ch for ch in text if unicodedata.category(ch)[0] != "C" or ch == " ")
    kept = " ".join(kept.split())
    return kept if len(kept) <= limit else kept[: limit - 1] + "…"


def _models_in(annotation: object) -> Iterable[type[BaseModel]]:
    if isinstance(annotation, type) and issubclass(annotation, BaseModel):
        yield annotation
        return
    if get_origin(annotation) is not None:  # list[...], X | None, Annotated[...]
        for arg in get_args(annotation):
            yield from _models_in(arg)


def field_names(model: type[BaseModel]) -> frozenset[str]:
    """Every field name in the model and the models nested in it."""
    names: set[str] = set()
    seen: set[type[BaseModel]] = set()
    todo = [model]
    while todo:
        current = todo.pop()
        if current in seen:
            continue
        seen.add(current)
        for name, field in current.model_fields.items():
            names.add(field.alias or name)
            todo.extend(_models_in(field.annotation))
    return frozenset(names)


def describe_errors(exc: ValidationError, model: type[BaseModel]) -> list[str]:
    """Field paths and rule messages, with any key the model invented masked as `<key>`."""
    known = field_names(model)
    problems: list[str] = []
    for error in exc.errors()[:MAX_PROBLEMS]:
        parts: list[str] = []
        for part in error["loc"]:
            if isinstance(part, int):
                parts.append(str(part))
            elif part in known and _SAFE_NAME.fullmatch(part):
                parts.append(part)
            else:
                parts.append("<key>")
        where = ".".join(parts) or "(the whole object)"
        problems.append(f"{where}: {_clean(str(error['msg']))}")
    more = exc.error_count() - len(problems)
    if more > 0:
        problems.append(f"and {more} more problems")
    return problems


_TOKEN = re.compile(r'"(?:[^"\\]++|\\.)*+(?:"|\\?\Z)|[\[\]{}]', re.DOTALL)
"""A JSON string, or one bracket. Possessive, and an unclosed string runs to the end of the text,
so every `"` matches once and the scan stays linear on hostile input."""


def _depth(text: str) -> int:
    """The deepest nesting of arrays and objects, counting brackets outside strings."""
    deepest = level = 0
    for match in _TOKEN.finditer(text):
        piece = match.group()
        if piece[0] == '"':
            continue
        level += 1 if piece in "[{" else -1
        deepest = max(deepest, level)
    return deepest


def parse_response[T: BaseModel](raw: str, schema: type[T]) -> T:
    """Validate a provider response into `schema`, or raise `OutputInvalid`."""
    text = raw.strip()
    if len(text) > MAX_RESPONSE_CHARS:
        raise OutputInvalid([f"the reply is longer than {MAX_RESPONSE_CHARS} characters"])
    fenced = _FENCE.match(text)
    if fenced:
        text = fenced.group("body").strip()
    if _depth(text) > MAX_JSON_DEPTH:
        raise OutputInvalid(["the reply is nested too deeply"])
    try:
        data = json.loads(text, object_pairs_hook=_no_duplicates, parse_constant=_no_constants)
    except json.JSONDecodeError as exc:
        raise OutputInvalid(
            [f"the reply is not valid JSON (line {exc.lineno}, column {exc.colno}): {exc.msg}"]
        ) from None
    except RecursionError:
        raise OutputInvalid(["the reply is nested too deeply"]) from None
    except ValueError as exc:
        raise OutputInvalid([_clean(str(exc))]) from None
    if not isinstance(data, dict):
        raise OutputInvalid(["the reply must be one JSON object"])
    try:
        return schema.model_validate_json(text, strict=True)
    except ValidationError as exc:
        raise OutputInvalid(describe_errors(exc, schema)) from None


def repair_note(problems: Iterable[str]) -> str:
    """The text appended to the user content for the one repair attempt."""
    lines = "\n".join(f"- {problem}" for problem in problems)
    return (
        "Your previous reply was rejected because it did not match the required JSON schema:\n"
        f"{lines}\n"
        "Reply again with one JSON object that matches the schema exactly. Respect every length "
        "and size limit, use only the allowed values, and add no other fields."
    )


def json_instruction(schema: Mapping[str, Any]) -> str:
    """Appended to the system prompt when the provider has no native schema mode."""
    return (
        "Reply with exactly one JSON object and nothing else: no prose and no code fence. "
        "It must match this JSON schema, including every limit in the descriptions:\n"
        + json.dumps(schema, sort_keys=True, ensure_ascii=True)
    )
