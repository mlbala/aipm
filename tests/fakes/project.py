"""A clinic `ProjectContext` for the prompt and context-file tests (build prompt 05).

Built the way `aipm prompt` and `aipm sync-context` build it: from an approved state snapshot (the
clinic fixtures) and a config holding the python-uv stack, through `build_context`, so gate argv
comes from `compile_gate`.
"""

from dataclasses import replace

from aipm.app.project_context import build_context
from aipm.config.schema import Config
from aipm.config.stacks import load_stack
from aipm.domain.models import ComponentInfo, FeatureInfo, ProjectContext, StateSnapshot, Task
from tests.golden.test_design_plan_golden import status_snapshot


def clinic_config(**overrides: object) -> Config:
    """A config with the python-uv stack's commands, as after G2 for a greenfield project."""
    stack = load_stack("python-uv").model_dump(mode="json", exclude_none=True)
    return Config.model_validate({"stack_template": "python-uv", **stack, **overrides})


def clinic_snapshot() -> StateSnapshot:
    """The approved clinic project with T-001 done and T-002 blocked (the status golden)."""
    return status_snapshot()


def clinic_context(**overrides: object) -> ProjectContext:
    """The clinic project's context, from the snapshot and the python-uv config."""
    return build_context(clinic_snapshot(), clinic_config(**overrides))


def clinic_task(task_id: str) -> Task:
    """One task of the clinic plan."""
    tasks = clinic_snapshot().tasks
    assert tasks is not None
    return next(t for t in tasks.tasks if t.id == task_id)


def hostile_context(text: str, ctx: ProjectContext | None = None) -> ProjectContext:
    """`ctx` with `text` in every model-written field: one-liner, features and components."""
    base = ctx if ctx is not None else clinic_context()
    return replace(
        base,
        one_liner=text,
        features=(*base.features, FeatureInfo("F-099", "must", text)),
        components=(*base.components, ComponentInfo("C-99", text[:40], ("src/x/**",), text)),
    )


def hostile_task(text: str, task: Task | None = None) -> Task:
    """`task` with `text` in its title, description and every acceptance criterion."""
    base = task if task is not None else clinic_task("T-003")
    criteria = [c.model_copy(update={"text": text[:500]}) for c in base.acceptance]
    return base.model_copy(
        update={"title": text[:120], "description": text[:4000], "acceptance": criteria}
    )
