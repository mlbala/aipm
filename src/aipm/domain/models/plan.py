"""The planner's proposed tasks: bounded shapes only (ARCHITECTURE §9).

A proposal is LLM output. These models check shape and size, nothing more: IDs, globs, gate
names, traces and package names are plain bounded strings here, so that every rule is applied,
and reported, by the plan validator (`aipm.domain.dag`), which turns proposals into `Task`s.
"""

from typing import Annotated

from pydantic import Field, StringConstraints

from aipm.domain.models.artifacts import TaskSize, TaskType
from aipm.domain.models.base import Str120, Str4000, StrictModel

ShortText = Annotated[str, StringConstraints(max_length=16)]
GlobText = Annotated[str, StringConstraints(max_length=512)]
GateText = Annotated[str, StringConstraints(max_length=32)]
Criterion = Annotated[str, StringConstraints(min_length=1, max_length=500)]

MAX_PROPOSED_TASKS = 200
"""The `tasks.yaml` cap (ARCHITECTURE §6.3); a larger reply fails schema validation."""


class ProposedDependency(StrictModel):
    """A new dependency the planner wants a task to add."""

    ecosystem: Annotated[str, StringConstraints(max_length=16)]
    name: Annotated[str, StringConstraints(max_length=214)]


class ProposedTask(StrictModel):
    """One task as the planner proposes it."""

    id: ShortText
    title: Str120
    description: Str4000
    type: TaskType
    traces: list[ShortText] = Field(max_length=20)
    depends_on: list[ShortText] = Field(max_length=20)
    owns_files: list[GlobText] = Field(max_length=64)
    reads_files: list[GlobText] = Field(max_length=64)
    deps_add: list[ProposedDependency] = Field(max_length=20)
    acceptance: list[Criterion] = Field(min_length=1, max_length=16)
    gates: list[GateText] = Field(max_length=16)
    size: TaskSize
