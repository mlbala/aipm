"""Process-wide setup for a CLI command: logging with redaction (ARCHITECTURE §17)."""

from pathlib import Path

from aipm.app.workspace import find_repo_root
from aipm.config.loader import user_redact_patterns
from aipm.domain.errors import AipmError
from aipm.llm.cache import ResponseCache
from aipm.observability.logging import configure_logging, log_dir
from aipm.observability.redaction import process_redactor
from aipm.security.paths import is_within
from aipm.security.redact import Redactor
from aipm.state.attempts import WriteLedger
from aipm.state.store import FileStateStore, open_store

_STDERR_LEVELS = ("warning", "info", "debug")


def configure(verbose: int, project: Path | None = None) -> Path | None:
    """Configure logging for one command; returns the JSON log file, if one could be opened.

    `-v` shows info on stderr and `-vv` debug; the file always records info and above.
    `project` is the `-C` directory. No log file is opened when the log directory lies inside
    that repository, as it does when a repository `.env` sets `HOME` or `XDG_STATE_HOME`.
    """
    root = _repo_root(project)
    stderr_level = _STDERR_LEVELS[min(max(verbose, 0), len(_STDERR_LEVELS) - 1)]
    return configure_logging(
        "info",
        json_lines=False,
        stderr_level=stderr_level,
        redactor=user_redactor(root),
        file=root is None or not is_within(log_dir(), root),
    )


def _repo_root(project: Path | None) -> Path | None:
    try:
        return find_repo_root(project)
    except AipmError:
        return None


def user_redactor(root: Path | None = None) -> Redactor:
    """The process redactor plus `security.extra_redact_patterns` from the user config file.

    Patterns from the repository or from `AIPM_*` variables are never used: a regex that
    backtracks without end would hang every redaction, and one that matches aipm's own sentences
    would erase them from prompts (red-team v0.1 review). `root` is the repository the command
    works on, which the user config must lie outside (by default, the one around the current
    directory). A user config that fails to load or lies inside falls back to the built-in
    patterns; the command itself reports the error.
    """
    try:
        patterns = user_redact_patterns(root)
    except AipmError:
        patterns = []
    return process_redactor(patterns)


def open_repo_store(root: Path, *, redactor: Redactor | None = None) -> FileStateStore:
    """The repository's `.pm/` store for a command: the user's redactor, and the write ledger
    that lets `verify` tell aipm's own `.pm/` writes from anyone else's (ADR-0021)."""
    return open_store(
        root,
        redactor=redactor if redactor is not None else user_redactor(root),
        ledger=WriteLedger(root),
    )


def llm_cache(store: FileStateStore) -> ResponseCache:
    """The LLM response cache in `.pm/cache/llm/` (ARCHITECTURE §14)."""
    return store
