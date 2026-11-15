"""Process-wide options of one CLI run that are not a command's own (ARCHITECTURE §16-§18).

`--no-plugins` and the repository decide which entry-point plugins may load (nothing is
imported until a registry needs them), and `--trace` turns on OpenTelemetry spans. Kept apart
from `aipm.app.runtime` so the CLI callback stays cheap.
"""

from collections.abc import Generator
from contextlib import contextmanager
from pathlib import Path

from aipm.app.workspace import find_repo_root
from aipm.config.locations import location_warnings
from aipm.domain.errors import AipmError
from aipm.observability import tracing
from aipm.plugins import loader


def configure(*, project: Path | None, plugins: bool, trace: bool) -> list[str]:
    """Record whether plugins may load and the repository they may never come from, and turn
    spans on with `--trace` (ADR-0027). Returns the warnings to print on every run: a moved
    config or state directory (v0.1 O-1), and `--trace` that cannot take effect."""
    try:
        root: Path | None = find_repo_root(project)
    except AipmError:
        root = None
    loader.configure(enabled=plugins, repo=root)
    warnings = location_warnings()
    trace_warning = tracing.configure_tracing(enabled=trace)
    if trace_warning is not None:
        warnings.append(trace_warning)
    return warnings


@contextmanager
def command_span(command: str) -> Generator[tracing.SpanHandle]:
    """The span of one CLI command; nothing when tracing is off."""
    with tracing.span("aipm.command", command=command) as span:
        yield span
