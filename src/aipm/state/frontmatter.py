"""Markdown front matter: YAML between `---` lines, then a free Markdown body (§6.2)."""

from aipm.domain.errors import SchemaError
from aipm.state.yamlio import dump_yaml, load_yaml

FENCE = "---"


def parse(text: str, *, source: str = "front matter") -> tuple[dict[str, object], str]:
    """Split a Markdown artifact into front matter and body. CRLF line endings become LF."""
    lines = text.replace("\r\n", "\n").split("\n")
    if lines[0] != FENCE:
        raise SchemaError(f"{source}: missing YAML front matter (the file must start with ---)")
    try:
        close = lines.index(FENCE, 1)
    except ValueError:
        raise SchemaError(f"{source}: front matter is not closed with a --- line") from None
    meta = load_yaml("\n".join(lines[1:close]) + "\n", source=source)
    if not isinstance(meta, dict):
        raise SchemaError(f"{source}: front matter must be a mapping")
    mapping: dict[object, object] = meta  # pyright: ignore[reportUnknownVariableType]
    body = "\n".join(lines[close + 1 :])
    return {str(key): value for key, value in mapping.items()}, body


def dump(meta: dict[str, object], body: str) -> str:
    """Join front matter and body."""
    return f"{FENCE}\n{dump_yaml(meta)}{FENCE}\n{body}"
