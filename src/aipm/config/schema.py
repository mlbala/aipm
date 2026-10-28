"""The configuration schema (ARCHITECTURE §15) and its key classes."""

from dataclasses import dataclass
from enum import StrEnum


class KeyClass(StrEnum):
    """How a repo-level value is treated (ARCHITECTURE §15, SECURITY.md §6 rule 5)."""

    USER_ONLY = "user-only"
    TIGHTEN_ONLY = "tighten-only"
    REPO_OK = "repo-ok"


@dataclass(frozen=True, slots=True)
class Config:
    """Placeholder for the merged, validated configuration (build prompt 02)."""
