"""Deterministic YAML with ruamel.yaml; aliases, anchors, tags and files over 1 MiB rejected."""


def load_yaml(text: str) -> object:
    """Parse YAML safely (ARCHITECTURE §6.2)."""
    raise NotImplementedError("v0.1: build prompt 02")


def dump_yaml(data: object) -> str:
    """Dump YAML in schema order with a trailing newline."""
    raise NotImplementedError("v0.1: build prompt 02")
