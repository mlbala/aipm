"""The append-only run journal for resume and audit (C-19, ARCHITECTURE §6.3, v0.3)."""

from collections.abc import Mapping
from pathlib import Path


def append_event(journal: Path, event: Mapping[str, object]) -> None:
    """Append one event and fsync."""
    raise NotImplementedError("v0.3: build prompt 07")
