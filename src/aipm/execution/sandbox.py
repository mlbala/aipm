"""Sandboxing with `srt` or a tool-native sandbox, plus network profiles (C-13, v0.2)."""

from collections.abc import Sequence
from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class SandboxProfile:
    """Filesystem and network rules for one process (placeholder, prompt 06)."""


def wrap(argv: Sequence[str], profile: SandboxProfile) -> tuple[str, ...]:
    """Wrap an argv so it runs inside the sandbox."""
    raise NotImplementedError("v0.2: build prompt 06")
