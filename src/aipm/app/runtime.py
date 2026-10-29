"""Process-wide setup for a CLI command: logging with redaction (ARCHITECTURE §17)."""

from pathlib import Path

from aipm.observability.logging import configure_logging

_STDERR_LEVELS = ("warning", "info", "debug")


def configure(verbose: int) -> Path | None:
    """Configure logging for one command; returns the JSON log file, if one could be opened.

    `-v` shows info on stderr and `-vv` debug; the file always records info and above.
    """
    stderr_level = _STDERR_LEVELS[min(max(verbose, 0), len(_STDERR_LEVELS) - 1)]
    return configure_logging("info", json_lines=False, stderr_level=stderr_level)
