"""Adapter registry; entry-point adapters arrive in v0.4 (ARCHITECTURE §18)."""

from aipm.adapters import claude_code
from aipm.adapters.base import ToolAdapter
from aipm.domain.errors import NotAvailable, UsageError
from aipm.domain.models import ToolName

V01_TOOLS = (ToolName.CLAUDE,)


def parse_tool(value: str | None, default: ToolName) -> ToolName:
    """`--tool` as a `ToolName`, or `default`; exit 2 for an unknown name."""
    if value is None:
        return default
    try:
        return ToolName(value.strip().lower())
    except ValueError:
        names = ", ".join(t.value for t in ToolName)
        raise UsageError(f"unknown tool {value!r}", hint=f"Use one of: {names}.") from None


def get_adapter(name: ToolName) -> ToolAdapter:
    """Return the adapter for a tool; only Claude Code exists in v0.1 (exit 2 otherwise)."""
    if name is ToolName.CLAUDE:
        return claude_code.create()
    raise NotAvailable(
        f"the {name.value} adapter is available in v0.4",
        hint="Use --tool claude, or run `aipm prompt` and paste the prompt into your agent.",
    )
