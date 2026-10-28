"""The only way to write `.pm/` (AGENTS.md rule 7): atomic, locked, redacted (ARCHITECTURE §5.3).

Security events are appended to `.pm/events.jsonl` through the store as well (§6.1).
"""

from contextlib import AbstractContextManager
from pathlib import Path
from typing import Protocol

from aipm.domain.models import Artifact, ArtifactKind


class StateStore(Protocol):
    """Load and save `.pm/` artifacts."""

    root: Path

    def load(self, kind: ArtifactKind) -> Artifact:
        """Load and validate an artifact; a newer schema_version exits 2."""
        ...

    def save(self, artifact: Artifact) -> str:
        """Write atomically after redaction and return the sha256."""
        ...

    def exists(self, kind: ArtifactKind) -> bool:
        """Return whether the artifact exists."""
        ...

    def sha256(self, kind: ArtifactKind) -> str | None:
        """Return the normalized hash, or None if missing."""
        ...

    def lock(self) -> AbstractContextManager[None]:
        """Hold the `.pm/` lock; raises `LockHeld` (exit 7) if another process has it."""
        ...


def open_store(repo_root: Path) -> StateStore:
    """Return the store for `<repo_root>/.pm`."""
    raise NotImplementedError("v0.1: build prompt 02")
