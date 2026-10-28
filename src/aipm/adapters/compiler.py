"""Prompt compiler: canonical TaskSpec from tasks.yaml, architecture and config, no LLM (§10.1)."""

from aipm.domain.models import ProjectContext, Task, TaskSpec


def compile_task_spec(task: Task, ctx: ProjectContext) -> TaskSpec:
    """Assemble the task spec deterministically; gate argv only through `compile_gate`."""
    raise NotImplementedError("v0.1: build prompt 05")
