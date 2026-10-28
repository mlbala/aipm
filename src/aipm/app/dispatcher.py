"""Dispatch one task attempt to a coding agent (C-18, ARCHITECTURE §12.4, v0.3)."""

from aipm.adapters.base import AgentResult, ToolAdapter
from aipm.domain.models import Task, Workspace


def dispatch(task: Task, adapter: ToolAdapter, ws: Workspace) -> AgentResult:
    """Run the agent for one attempt, sandboxed with the api-only network profile."""
    raise NotImplementedError("v0.3: build prompt 07")
