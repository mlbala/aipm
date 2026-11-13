"""The adapter registry: the four built-in coding tools (ARCHITECTURE §11, §18)."""

from collections.abc import Callable

from aipm.adapters import claude_code, codex, copilot, gemini
from aipm.adapters.base import ToolAdapter
from aipm.domain.errors import UsageError
from aipm.domain.models import ToolName

_FACTORIES: dict[ToolName, Callable[[], ToolAdapter]] = {
    ToolName.CLAUDE: claude_code.create,
    ToolName.CODEX: codex.create,
    ToolName.COPILOT: copilot.create,
    ToolName.GEMINI: gemini.create,
}


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
    """Return the adapter for a tool. Copilot's renders prompts and context files only
    (ADR-0025): its `detect` never reports it dispatchable."""
    return _FACTORIES[name]()
