"""Adapter registry; entry-point adapters arrive in v0.4 (ARCHITECTURE §18)."""

from aipm.adapters.base import ToolAdapter
from aipm.domain.models import ToolName


def get_adapter(name: ToolName) -> ToolAdapter:
    """Return the adapter for a tool."""
    raise NotImplementedError("v0.1: build prompt 05")
