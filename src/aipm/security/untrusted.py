"""Typed untrusted content and its Jinja filter (SECURITY.md §7.2)."""

from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class Untrusted:
    """Text from a T2 source, or any `.pm/` artifact rendered into a prompt."""

    text: str
    source: str


def untrusted_filter(value: Untrusted) -> str:
    """Sanitize, neutralize closing tags and wrap in a nonce-delimited untrusted block."""
    raise NotImplementedError("v0.1: build prompt 02")
