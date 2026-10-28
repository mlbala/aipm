"""The only module that may start a process (C-12, SECURITY.md §10 rule 6).

argv lists only, a timeout, a constructed environment (never a copy of `os.environ`), a new
process group, stdin closed unless given, and an output cap.
"""

from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path

from aipm.execution.sandbox import SandboxProfile


@dataclass(frozen=True, slots=True)
class ProcessResult:
    """The outcome of one process run."""

    argv: tuple[str, ...]
    returncode: int | None
    stdout: bytes
    stderr: bytes
    timed_out: bool
    truncated: bool
    duration_s: float


def run_safe(
    argv: Sequence[str],
    *,
    cwd: Path,
    env: Mapping[str, str],
    timeout_s: float,
    stdin: bytes | None = None,
    max_output_bytes: int = 2_000_000,
    sandbox: SandboxProfile | None = None,
) -> ProcessResult:
    """Run one process safely and return its result."""
    raise NotImplementedError("v0.1: build prompt 02")


async def run_safe_async(
    argv: Sequence[str],
    *,
    cwd: Path,
    env: Mapping[str, str],
    timeout_s: float,
    stdin: bytes | None = None,
    max_output_bytes: int = 2_000_000,
    sandbox: SandboxProfile | None = None,
) -> ProcessResult:
    """The asyncio variant of `run_safe`."""
    raise NotImplementedError("v0.1: build prompt 02")
