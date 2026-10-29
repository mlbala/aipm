"""The `.pm/` file layout (ARCHITECTURE §6.1)."""

import hashlib
import os
from pathlib import Path

from aipm.domain.errors import UsageError
from aipm.domain.models import ArtifactKind, RepoId
from aipm.domain.models.base import ADR_DIR, ARTIFACT_FILES

PM_DIR = ".pm"
PROMPTS_DIR = "prompts"
EVENTS_FILE = "events.jsonl"
LOCK_FILE = ".lock"
GITIGNORE_FILE = ".gitignore"
GITIGNORE_TEXT = (
    "# Written by aipm: local state that is never committed (ARCHITECTURE §6.1).\n"
    "runs/\n"
    "cache/\n"
    "events.jsonl\n"
    ".lock\n"
    "*.tmp-*\n"
)

__all__ = [
    "ADR_DIR",
    "ARTIFACT_FILES",
    "EVENTS_FILE",
    "GITIGNORE_FILE",
    "GITIGNORE_TEXT",
    "LOCK_FILE",
    "PM_DIR",
    "PROMPTS_DIR",
    "artifact_name",
    "artifact_path",
    "pm_root",
    "repo_id",
]


def pm_root(repo_root: Path) -> Path:
    """Return the `.pm/` directory of a repository."""
    return repo_root / PM_DIR


def artifact_name(kind: ArtifactKind) -> str:
    """Return the file name of an artifact inside `.pm/`."""
    name = ARTIFACT_FILES.get(kind)
    if name is None:
        raise UsageError(f"{kind.value} is not a single .pm/ file")
    return name


def artifact_path(repo_root: Path, kind: ArtifactKind) -> Path:
    """Return the path of an artifact file."""
    return pm_root(repo_root) / artifact_name(kind)


def repo_id(repo_root: Path) -> RepoId:
    """The first 16 hex characters of sha256(realpath(repo_root)) (ARCHITECTURE §6.1)."""
    real = os.path.realpath(repo_root)
    return RepoId(hashlib.sha256(real.encode("utf-8", errors="surrogateescape")).hexdigest()[:16])
