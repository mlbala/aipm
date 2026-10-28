"""The JSON envelope and the exit codes (ARCHITECTURE §16.1, §16.2)."""

import json

import pytest

from aipm.cli.errors import ExitCode, dumps, envelope, error_envelope
from aipm.domain import errors


def test_exit_codes_match_the_spec() -> None:
    assert {code.name: int(code) for code in ExitCode} == {
        "OK": 0,
        "INTERNAL": 1,
        "USAGE": 2,
        "VERIFICATION_FAILED": 3,
        "HUMAN_INPUT_REQUIRED": 4,
        "BUDGET_EXCEEDED": 5,
        "SECURITY_VIOLATION": 6,
        "LOCK_HELD": 7,
        "MISSING_TOOL": 8,
        "INTERRUPTED": 130,
    }


@pytest.mark.parametrize(
    ("error_type", "exit_code"),
    [
        (errors.AipmError, ExitCode.INTERNAL),
        (errors.UsageError, ExitCode.USAGE),
        (errors.NotAvailable, ExitCode.USAGE),
        (errors.NotImplementedYet, ExitCode.USAGE),
        (errors.VerificationFailed, ExitCode.VERIFICATION_FAILED),
        (errors.HumanInputRequired, ExitCode.HUMAN_INPUT_REQUIRED),
        (errors.BudgetExceeded, ExitCode.BUDGET_EXCEEDED),
        (errors.PolicyViolation, ExitCode.SECURITY_VIOLATION),
        (errors.LockHeld, ExitCode.LOCK_HELD),
        (errors.MissingCapability, ExitCode.MISSING_TOOL),
    ],
)
def test_each_error_carries_its_exit_code(
    error_type: type[errors.AipmError], exit_code: ExitCode
) -> None:
    error = error_type("message", hint="hint")
    env = error_envelope(error, command="x", version="1.0")
    assert env["exit_code"] == int(exit_code)
    assert env["ok"] is False
    assert env["errors"] == [{"code": error_type.code, "message": "message", "hint": "hint"}]


def test_ok_only_for_exit_code_zero() -> None:
    assert envelope(command="status", version="1.0", exit_code=ExitCode.OK)["ok"] is True
    assert envelope(command="status", version="1.0", exit_code=ExitCode.USAGE)["ok"] is False


@pytest.mark.parametrize(
    "hostile",
    [
        "\x1b]52;c;Y3VybCBldmlsIHwgc2g=\x07",  # OSC 52 clipboard write
        "\x1b[2J\x1b[H",  # CSI clear screen
        "\x9b31m",  # C1 CSI
        "\u202eevil",  # bidi override
    ],
)
def test_dumps_never_emits_raw_control_characters(hostile: str) -> None:
    env = error_envelope(errors.UsageError(hostile), command="x", version="1.0")
    text = dumps(env)
    assert text.isascii()
    assert not any(ord(ch) < 0x20 for ch in text)
    assert json.loads(text)["errors"][0]["message"] == hostile
