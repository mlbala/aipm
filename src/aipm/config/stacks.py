"""Stack templates (ARCHITECTURE §13.1): data-only YAML shipped inside the package.

Templates are read from package resources only, never from the repository.
"""

import re
from importlib.resources import files

from pydantic import Field, ValidationError

from aipm.config.schema import ArgvPrefixes, RelPathSyntax
from aipm.domain.errors import SchemaError, UsageError
from aipm.domain.models import GateDef, PrepareDef, StrictModel
from aipm.domain.models.artifacts import GateName
from aipm.state.yamlio import load_yaml

_NAME = re.compile(r"[a-z0-9][a-z0-9\-]{0,39}")


class StackTemplate(StrictModel):
    """A stack's argv prefixes, test roots, prepare step and gate menu."""

    allowed_executables: ArgvPrefixes = Field(min_length=1)
    test_roots: list[RelPathSyntax] = Field(default_factory=list[str], max_length=10)
    prepare: PrepareDef | None = None
    gates: dict[GateName, GateDef] = Field(default_factory=dict[str, GateDef], max_length=20)


def available_stacks() -> list[str]:
    """The names of the shipped stack templates."""
    root = files("aipm.config") / "stacks"
    return sorted(
        entry.name.removesuffix(".yaml")
        for entry in root.iterdir()
        if entry.name.endswith(".yaml") and _NAME.fullmatch(entry.name.removesuffix(".yaml"))
    )


def load_stack(name: str) -> StackTemplate:
    """Load a shipped stack template by name, or raise `UsageError` (exit 2)."""
    known = available_stacks()
    if name not in known:
        raise UsageError(
            f"unknown stack template {name!r}",
            hint=f"Available: {', '.join(known)}. More arrive in v0.2 (ARCHITECTURE §13.1).",
        )
    text = (files("aipm.config") / "stacks" / f"{name}.yaml").read_text(encoding="utf-8")
    try:
        return StackTemplate.model_validate(load_yaml(text, source=f"stack {name}"))
    except ValidationError as exc:  # a packaging bug, not user input
        raise SchemaError(f"stack template {name} is invalid: {exc.error_count()} errors") from None
