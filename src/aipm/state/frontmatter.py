"""Markdown front matter: YAML between `---` lines, then a free Markdown body (§6.2)."""


def parse(text: str) -> tuple[dict[str, object], str]:
    """Split a Markdown artifact into front matter and body."""
    raise NotImplementedError("v0.1: build prompt 02")


def dump(meta: dict[str, object], body: str) -> str:
    """Join front matter and body."""
    raise NotImplementedError("v0.1: build prompt 02")
