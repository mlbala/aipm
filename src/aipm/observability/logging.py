"""Structured logging; every record passes through the redactor (ARCHITECTURE §17).

Human-readable lines go to stderr, JSON lines to a file in `<user_state_dir>/aipm/logs/`. Each
handler first strips terminal escape sequences and control characters, then redacts (with a
redactor built from the full environment), so a log line can neither leak a secret, even one
split by an escape sequence, nor drive the terminal. A log directory that cannot be created only
disables the file.
"""

import json
import logging
import os
import sys
from datetime import UTC, datetime
from pathlib import Path

import platformdirs

from aipm.observability.redaction import process_redactor
from aipm.security.redact import Redactor
from aipm.security.sanitize import strip_terminal_escapes

LOGGER_NAME = "aipm"
_LEVELS = {
    "debug": logging.DEBUG,
    "info": logging.INFO,
    "warning": logging.WARNING,
    "error": logging.ERROR,
}


def log_dir() -> Path:
    """`<user_state_dir>/aipm/logs`."""
    return Path(platformdirs.user_state_dir("aipm", appauthor=False)) / "logs"


class _EscapeFilter(logging.Filter):
    """Runs before redaction: folds the arguments into the message and formats the traceback,
    then strips escapes and control characters. A secret split by an escape sequence, as colored
    tool output produces, is therefore whole when the redactor sees it (red-team v0.1, RT01-4).
    """

    def filter(self, record: logging.LogRecord) -> bool:
        try:
            message = record.getMessage()
        except (TypeError, ValueError):
            message = str(record.msg)
        record.msg = strip_terminal_escapes(message)
        record.args = None
        if record.exc_info and not record.exc_text:
            record.exc_text = logging.Formatter().formatException(record.exc_info)
        if record.exc_text:
            record.exc_text = strip_terminal_escapes(record.exc_text)
        return True


class _JsonFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        entry: dict[str, object] = {
            "ts": datetime.fromtimestamp(record.created, UTC).isoformat(timespec="milliseconds"),
            "level": record.levelname.lower(),
            "logger": record.name,
            "message": record.getMessage(),
        }
        if record.exc_text:
            entry["exception"] = record.exc_text
        return json.dumps(entry, ensure_ascii=True)


def _level(name: str) -> int:
    return _LEVELS.get(name.lower(), logging.INFO)


def _open_log_file(directory: Path) -> Path:
    directory.mkdir(mode=0o700, parents=True, exist_ok=True)
    path = directory / f"aipm-{datetime.now(UTC):%Y%m%d}.log"
    fd = os.open(path, os.O_WRONLY | os.O_APPEND | os.O_CREAT | os.O_NOFOLLOW, 0o600)
    os.close(fd)
    return path


def configure_logging(
    level: str,
    *,
    json_lines: bool,
    stderr_level: str = "warning",
    directory: Path | None = None,
    redactor: Redactor | None = None,
) -> Path | None:
    """Configure stderr logging and the JSON log file; returns the log file, if any.

    `level` is the file's level (`logging.level`), `stderr_level` the terminal's (raised by
    `-v`). With `json_lines`, stderr gets JSON lines too.
    """
    logger = logging.getLogger(LOGGER_NAME)
    for handler in list(logger.handlers):
        logger.removeHandler(handler)
        handler.close()
    logger.propagate = False
    logger.setLevel(min(_level(level), _level(stderr_level)))
    redacting = (redactor if redactor is not None else process_redactor()).logging_filter()
    escapes = _EscapeFilter()

    terminal = logging.StreamHandler(sys.stderr)
    terminal.setLevel(_level(stderr_level))
    terminal.setFormatter(
        _JsonFormatter() if json_lines else logging.Formatter("aipm: %(levelname)s: %(message)s")
    )
    terminal.addFilter(escapes)
    terminal.addFilter(redacting)
    logger.addHandler(terminal)

    try:
        path = _open_log_file(directory if directory is not None else log_dir())
    except OSError:
        return None
    file_handler = logging.FileHandler(path, encoding="utf-8")
    file_handler.setLevel(_level(level))
    file_handler.setFormatter(_JsonFormatter())
    file_handler.addFilter(escapes)
    file_handler.addFilter(redacting)
    logger.addHandler(file_handler)
    return path
