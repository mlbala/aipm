"""Secret redaction (SECURITY.md §8).

The redactor takes an environment snapshot instead of reading `os.environ`, which keeps
this module pure. The gateway, `StateStore` and logging build it from the full environment.
"""

from collections.abc import Mapping, Sequence


class Redactor:
    """Replace secret values and known token formats with «REDACTED:<kind>»."""

    def __init__(self, env: Mapping[str, str], *, extra_patterns: Sequence[str] = ()) -> None:
        raise NotImplementedError("v0.1: build prompt 02")

    def redact(self, text: str) -> str:
        """Return `text` with every secret replaced."""
        raise NotImplementedError("v0.1: build prompt 02")

    def contains_secret(self, text: str) -> bool:
        """Return whether `text` still matches a high-confidence secret pattern."""
        raise NotImplementedError("v0.1: build prompt 02")
