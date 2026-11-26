"""Process-wide setup for a CLI command: logging with redaction (ARCHITECTURE §17)."""

import logging
import os
from pathlib import Path

from aipm.app.workspace import find_repo_root
from aipm.config import keychain
from aipm.config.loader import user_api_key_env, user_redact_patterns
from aipm.domain.errors import AipmError
from aipm.llm.cache import ResponseCache
from aipm.observability.logging import configure_logging, log_dir
from aipm.observability.redaction import process_redactor
from aipm.security.paths import is_within
from aipm.security.redact import Redactor
from aipm.state.attempts import WriteLedger
from aipm.state.store import FileStateStore, open_store

_STDERR_LEVELS = ("warning", "info", "debug")

KEY_COMMANDS = frozenset({"discover", "design", "plan", "verify", "build", "run", "auto", "doctor"})
"""The commands that may call the model or start a coding agent, plus `doctor`, which reports
where each key comes from. Only these read keys from the OS keychain (ADR-0033): every other
command skips the lookups, so a locked keychain never prompts for `aipm status`."""
_log = logging.getLogger(__name__)


def configure(verbose: int, project: Path | None = None, command: str | None = None) -> Path | None:
    """Configure logging for one command; returns the JSON log file, if one could be opened.

    `-v` shows info on stderr and `-vv` debug; the file always records info and above.
    `project` is the `-C` directory. No log file is opened when the log directory lies inside
    that repository, as it does when a repository `.env` sets `HOME` or `XDG_STATE_HOME`.
    `command` is the aipm command being run: keys are read from the keychain only for the
    commands in `KEY_COMMANDS` (or when no command is named).
    """
    root = _repo_root(project)
    stderr_level = _STDERR_LEVELS[min(max(verbose, 0), len(_STDERR_LEVELS) - 1)]
    key_warnings = prime_keys(root) if command is None or command in KEY_COMMANDS else []
    log_file = configure_logging(
        "info",
        json_lines=False,
        stderr_level=stderr_level,
        redactor=user_redactor(root),
        file=root is None or not is_within(log_dir(), root),
    )
    for warning in key_warnings:
        _log.warning("%s", warning)
    return log_file


def prime_keys(root: Path | None) -> list[str]:
    """Read the keys aipm may need from the OS keychain, before any redactor is built (ADR-0033).

    Only the shipped adapters' key names and the user config's `llm.api_key_env` are looked up.
    """
    names = [*keychain.AGENT_KEY_NAMES]
    own = user_api_key_env(root)
    if own is not None:
        names.append(own)
    return keychain.prime(names, os.environ)


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


def checked_user_redactor(root: Path) -> Redactor:
    """`user_redactor`, but a user config that cannot be used is the command's error (exit 6
    for an `AIPM_CONFIG` that names a missing file), not a fall back to the built-in patterns.
    For the commands that load no configuration of their own: the phase report outside an
    initialized repository, and `aipm task` (v0.1 O-2)."""
    return process_redactor(user_redact_patterns(root))


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
