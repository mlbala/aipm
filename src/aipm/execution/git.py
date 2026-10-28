"""Hardened git calls (SECURITY.md §11): hooks off, no fsmonitor, no external diff (C-14)."""

from pathlib import Path

from aipm.domain.models import ChangeSet


def change_set(repo: Path, base_sha: str) -> ChangeSet:
    """Collect the facts that post-change checks inspect."""
    raise NotImplementedError("v0.2: build prompt 06")
