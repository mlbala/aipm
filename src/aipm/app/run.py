"""`aipm run`: one attempt loop for one task (§12.4), through the same harness as `build`."""

from pathlib import Path

from aipm.app import build
from aipm.app.build import BuildOptions, BuildResult
from aipm.app.build_loop import ProgressSink


def run(
    project: Path | None,
    *,
    task_id: str,
    tool: str | None,
    timeout: str | None,
    budget: float | None,
    dry_run: bool,
    accept_stale: bool,
    no_cache: bool = False,
    progress: ProgressSink | None = None,
) -> BuildResult:
    """Run the use case: build `task_id` alone, with `--parallel 1`."""
    options = BuildOptions(
        kind="run", task_id=task_id, tool=tool, timeout=timeout, budget=budget, dry_run=dry_run,
        accept_stale=accept_stale, no_cache=no_cache,
    )  # fmt: skip
    return build.run(project, options, progress=progress)
