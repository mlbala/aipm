"""The command policy (SECURITY.md §10). Pure: no executable resolution happens here.

`compile_gate` turns a trusted gate definition into an argv. The trust store resolves
executables with `shutil.which` at trust time.
"""

from collections.abc import Sequence
from dataclasses import dataclass
from pathlib import Path

from aipm.domain.models import GateDef, ToolName
from aipm.security.paths import SafeRelPath

type Argv = tuple[str, ...]


@dataclass(frozen=True, slots=True)
class CommandPolicy:
    """Allowed argv prefixes and the user-level extras (placeholder, prompt 02)."""


def compile_gate(
    gate: GateDef,
    *,
    paths: Sequence[SafeRelPath],
    policy: CommandPolicy,
    report_file: Path | None = None,
) -> Argv:
    """Expand placeholders and check the result, or raise `PolicyViolation` (exit 6)."""
    raise NotImplementedError("v0.1: build prompt 02")


def check_forbidden_flags(tool: ToolName, argv: Argv) -> None:
    """Raise `PolicyViolation` if `argv` holds a forbidden flag (ARCHITECTURE §11)."""
    raise NotImplementedError("v0.1: build prompt 02")
