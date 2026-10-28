"""PRD writer (ARCHITECTURE §14.1)."""

from aipm.roles.base import Role


def create() -> Role[object, object]:
    """Return the role."""
    raise NotImplementedError("v0.1: build prompt 03")
