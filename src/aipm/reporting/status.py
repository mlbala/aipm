"""The status view: counts, blocked tasks, security events, spend (ARCHITECTURE §17)."""

from collections.abc import Sequence

from aipm.domain.models import Task


def render_status(tasks: Sequence[Task]) -> str:
    """Render the status report."""
    raise NotImplementedError("v0.1: build prompt 04")
