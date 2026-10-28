"""The worksheet generated from tasks.yaml (ARCHITECTURE §6.1)."""

from collections.abc import Sequence

from aipm.domain.models import Task


def render_worksheet(tasks: Sequence[Task]) -> str:
    """Render `worksheet.md`."""
    raise NotImplementedError("v0.1: build prompt 04")
