"""Task worktrees outside the repository and the integration branch (§12.2, v0.3)."""

from pathlib import Path


def create_worktree(repo: Path, task_id: str) -> Path:
    """Create the task's worktree and return its path."""
    raise NotImplementedError("v0.3: build prompt 07")
