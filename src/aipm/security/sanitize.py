"""L1 input hygiene (SECURITY.md §7.1): Unicode clean-up, control and escape removal."""

from collections.abc import Sequence


def sanitize_text(text: str) -> str:
    """Normalize Unicode and remove invisible and control characters. Idempotent."""
    raise NotImplementedError("v0.1: build prompt 02")


def strip_terminal_escapes(text: str) -> str:
    """Remove ANSI CSI and OSC sequences before text reaches a terminal (I-6)."""
    raise NotImplementedError("v0.1: build prompt 02")


def sanitize_for_context(text: str, *, allowed_url_domains: Sequence[str]) -> str:
    """Clean a field for a context file: L1, HTML comments and non-allowlisted URLs removed."""
    raise NotImplementedError("v0.1: build prompt 02")
