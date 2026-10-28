"""The user-level trust store (C-21, SECURITY.md §6), outside the repository.

Resolves each executable with `shutil.which` at trust time; the absolute paths are part of
the surface hash. `--yes` never writes here.
"""

from typing import Protocol

from aipm.config.schema import Config
from aipm.domain.models import RepoId


class TrustStore(Protocol):
    """Per-user, per-machine approval of a repository's execution surface."""

    def surface_hash(self, cfg: Config) -> str:
        """Return the canonical hash of the execution surface."""
        ...

    def is_trusted(self, repo: RepoId, surface_hash: str) -> bool:
        """Return whether this exact surface was trusted for the repository."""
        ...

    def trust(self, repo: RepoId, surface_hash: str, summary: str) -> None:
        """Record trust (only after interactive confirmation or `--confirm`)."""
        ...


def default_trust_store() -> TrustStore:
    """Return the store at `<user_state_dir>/aipm/trust.json` (mode 0600)."""
    raise NotImplementedError("v0.1: build prompt 02")
