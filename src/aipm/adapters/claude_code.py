"""Claude Code adapter: render in v0.1, dispatch in v0.3 (§11)."""

from aipm.adapters.base import ToolAdapter


def create() -> ToolAdapter:
    """Return the adapter."""
    raise NotImplementedError("v0.1: build prompt 05")
