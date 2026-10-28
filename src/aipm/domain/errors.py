"""Exit codes and the error hierarchy (ARCHITECTURE §16.1).

Every error aipm raises on purpose is an `AipmError` that carries its exit code and a
stable error code for the JSON envelope. Only the CLI turns them into a process exit.
"""

from enum import IntEnum
from typing import ClassVar


class ExitCode(IntEnum):
    """Process exit codes (ARCHITECTURE §16.1)."""

    OK = 0
    INTERNAL = 1
    USAGE = 2
    VERIFICATION_FAILED = 3
    HUMAN_INPUT_REQUIRED = 4
    BUDGET_EXCEEDED = 5
    SECURITY_VIOLATION = 6
    LOCK_HELD = 7
    MISSING_TOOL = 8
    INTERRUPTED = 130


class AipmError(Exception):
    """An expected failure with an exit code and a stable error code."""

    exit_code: ClassVar[ExitCode] = ExitCode.INTERNAL
    code: ClassVar[str] = "INTERNAL_ERROR"

    def __init__(self, message: str, *, hint: str | None = None) -> None:
        super().__init__(message)
        self.message = message
        self.hint = hint


class UsageError(AipmError):
    """Usage, configuration or precondition error, including a wrong phase."""

    exit_code = ExitCode.USAGE
    code = "USAGE"


class NotAvailable(UsageError):
    """The command belongs to a later milestone."""

    code = "NOT_AVAILABLE"


class NotImplementedYet(UsageError):
    """A v0.1 command whose build prompt has not run yet."""

    code = "NOT_IMPLEMENTED"


class InputRejected(UsageError):
    """Untrusted input is too large, binary or not valid UTF-8 (SECURITY.md §7.1)."""

    code = "INPUT_REJECTED"


class SchemaError(UsageError):
    """A `.pm/` file or a config layer fails validation, or has a newer schema_version."""

    code = "SCHEMA_ERROR"


class VerificationFailed(AipmError):
    """Gates or checks failed, or `sync-context --check` found drift."""

    exit_code = ExitCode.VERIFICATION_FAILED
    code = "VERIFICATION_FAILED"


class HumanInputRequired(AipmError):
    """Human input is needed but the run is non-interactive."""

    exit_code = ExitCode.HUMAN_INPUT_REQUIRED
    code = "HUMAN_INPUT_REQUIRED"


class BudgetExceeded(AipmError):
    """A budget or timeout was exceeded."""

    exit_code = ExitCode.BUDGET_EXCEEDED
    code = "BUDGET_EXCEEDED"


class PolicyViolation(AipmError):
    """A security policy was violated (blocked command, protected path, untrusted surface)."""

    exit_code = ExitCode.SECURITY_VIOLATION
    code = "POLICY_VIOLATION"


class LockHeld(AipmError):
    """Another aipm process holds the `.pm/` lock."""

    exit_code = ExitCode.LOCK_HELD
    code = "LOCK_HELD"


class MissingCapability(AipmError):
    """A required external tool or capability is missing or incompatible."""

    exit_code = ExitCode.MISSING_TOOL
    code = "MISSING_CAPABILITY"
