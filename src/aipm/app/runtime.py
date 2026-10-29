"""Process-wide setup for a CLI command: logging with redaction (ARCHITECTURE §17)."""

from pathlib import Path

from aipm.config.loader import load_config
from aipm.domain.errors import AipmError
from aipm.observability.logging import configure_logging
from aipm.observability.redaction import process_redactor
from aipm.security.redact import Redactor

_STDERR_LEVELS = ("warning", "info", "debug")


def configure(verbose: int) -> Path | None:
    """Configure logging for one command; returns the JSON log file, if one could be opened.

    `-v` shows info on stderr and `-vv` debug; the file always records info and above.
    """
    stderr_level = _STDERR_LEVELS[min(max(verbose, 0), len(_STDERR_LEVELS) - 1)]
    return configure_logging(
        "info", json_lines=False, stderr_level=stderr_level, redactor=user_redactor()
    )


def user_redactor() -> Redactor:
    """The process redactor plus `security.extra_redact_patterns` from the user's own config.

    Repository patterns are not used yet: a repo-supplied regex could make redaction hang or
    erase prompt boundaries (open question for an ADR). A user config that fails to load
    falls back to the built-in patterns; the command itself reports the error.
    """
    try:
        patterns = load_config(None).config.security.extra_redact_patterns
    except AipmError:
        patterns = []
    return process_redactor(patterns)
