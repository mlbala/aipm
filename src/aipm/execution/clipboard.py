"""Copying a prompt to the clipboard for `aipm prompt --copy` (ARCHITECTURE §12.7).

Uses `pbcopy`, `wl-copy` or `xclip`, whichever is present, resolved to an absolute path and run
through `run_safe` with the text on stdin and a constructed environment: the base allowlist plus
the display variables the Linux tools need, nothing else. No tool, or a failing one, is not an
error; the caller prints a hint.
"""

import os
import shutil
import sys
from collections.abc import Mapping
from pathlib import Path

from aipm.domain.errors import AipmError
from aipm.execution.process import build_env, run_safe

CLIPBOARD_TIMEOUT_S = 10.0
DISPLAY_ENV = ("DISPLAY", "WAYLAND_DISPLAY", "XDG_RUNTIME_DIR")

_TOOLS: tuple[tuple[str, tuple[str, ...]], ...] = (
    ("pbcopy", ()),
    ("wl-copy", ()),
    ("xclip", ("-selection", "clipboard")),
)


def _candidates(environ: Mapping[str, str], platform: str) -> list[tuple[str, tuple[str, ...]]]:
    if platform == "darwin":
        return [_TOOLS[0]]
    found: list[tuple[str, tuple[str, ...]]] = []
    if environ.get("WAYLAND_DISPLAY"):
        found.append(_TOOLS[1])
    if environ.get("DISPLAY"):
        found.append(_TOOLS[2])
    return found


def copy_text(
    text: str,
    *,
    cwd: Path,
    environ: Mapping[str, str] | None = None,
    platform: str = sys.platform,
) -> str | None:
    """Copy `text`; return the tool's name, or None when no tool is present or it failed."""
    env_source = os.environ if environ is None else environ
    display = {name: env_source[name] for name in DISPLAY_ENV if env_source.get(name)}
    for name, args in _candidates(env_source, platform):
        path = shutil.which(name)
        if path is None:
            continue
        try:
            result = run_safe(
                [path, *args],
                cwd=cwd,
                env=build_env(extra=display, source=env_source),
                timeout_s=CLIPBOARD_TIMEOUT_S,
                stdin=text.encode("utf-8"),
                max_output_bytes=4096,
            )
        except (AipmError, OSError):
            continue
        if result.returncode == 0 and not result.timed_out:
            return name
    return None
