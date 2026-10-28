"""Context files: AGENTS.md and CLAUDE.md in v0.1 (ARCHITECTURE §10.2).

Gate commands are rendered only from `compile_gate` output, and only when trusted.
"""

from aipm.domain.models import GeneratedFile, ProjectContext


def generate(ctx: ProjectContext) -> list[GeneratedFile]:
    """Render every context file from approved, sanitized fields."""
    raise NotImplementedError("v0.1: build prompt 05")
