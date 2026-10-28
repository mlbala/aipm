"""Acceptance-criteria reviewer, veto only (ADR-0007)."""

from aipm.roles.base import Role


def create() -> Role[object, object]:
    """Return the role."""
    raise NotImplementedError("v0.2: build prompt 06")
