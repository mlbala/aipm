"""Process-wide options of one CLI run that are not a command's own (ARCHITECTURE §16-§18).

`--no-plugins` and the repository decide which entry-point plugins may load (nothing is
imported until a registry needs them), and `--trace` turns on OpenTelemetry spans. Kept apart
from `aipm.app.runtime` so the CLI callback stays cheap.
"""

from pathlib import Path

from aipm.app.workspace import find_repo_root
from aipm.domain.errors import AipmError
from aipm.plugins import loader


def configure(*, project: Path | None, plugins: bool) -> None:
    """Record whether plugins may load, and the repository they may never come from."""
    try:
        root: Path | None = find_repo_root(project)
    except AipmError:
        root = None
    loader.configure(enabled=plugins, repo=root)
