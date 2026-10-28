"""The JSON envelope (ARCHITECTURE §16.2). Re-exports `ExitCode` from `aipm.domain.errors`.

Every command run with `--json` prints exactly one envelope to stdout; logs go to stderr.
"""

import json
from typing import TypedDict

from aipm.domain.errors import AipmError, ExitCode

__all__ = ["Envelope", "ErrorItem", "ExitCode", "dumps", "envelope", "error_envelope"]


class ErrorItem(TypedDict):
    """One entry of the envelope's `errors` list."""

    code: str
    message: str
    hint: str | None


class Envelope(TypedDict):
    """The machine-readable result of one command."""

    ok: bool
    command: str
    version: str
    exit_code: int
    data: dict[str, object]
    errors: list[ErrorItem]


def envelope(
    *,
    command: str,
    version: str,
    exit_code: ExitCode,
    data: dict[str, object] | None = None,
    errors: list[ErrorItem] | None = None,
) -> Envelope:
    """Build an envelope; `ok` is true only for exit code 0."""
    return {
        "ok": exit_code is ExitCode.OK,
        "command": command,
        "version": version,
        "exit_code": int(exit_code),
        "data": data if data is not None else {},
        "errors": errors if errors is not None else [],
    }


def error_envelope(error: AipmError, *, command: str, version: str) -> Envelope:
    """Build the envelope for a failed command."""
    item: ErrorItem = {"code": error.code, "message": error.message, "hint": error.hint}
    return envelope(command=command, version=version, exit_code=error.exit_code, errors=[item])


def dumps(env: Envelope) -> str:
    """Serialize with `json.dumps` only (SECURITY.md §7.10).

    `ensure_ascii=True` escapes every non-ASCII character, including C1 control codes, so
    the envelope can never carry a raw terminal escape sequence.
    """
    return json.dumps(env, ensure_ascii=True)
