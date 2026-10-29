"""CLI smoke tests: every command from ARCHITECTURE §16 is registered, with its flags.

Until each command's build prompt runs, v0.1 commands exit 2 with "not implemented yet" and
later-milestone commands exit 2 with "available in vX.Y".
"""

import json
from pathlib import Path

import pytest
from typer.testing import CliRunner

from aipm import __version__
from aipm.cli.main import app

runner = CliRunner()

# Command -> flags it must offer (ARCHITECTURE §16).
COMMAND_FLAGS: dict[str, list[str]] = {
    "init": ["--provider", "--tool", "--stack", "--force"],
    "doctor": [],
    "trust": ["--show", "--revoke", "--confirm"],
    "discover": [
        "--from", "--answers", "--defaults", "--edit", "--max-rounds", "--threshold",
        "--accept-risk",
    ],
    "approve": ["--yes"],
    "design": ["--regenerate", "--accept-risk", "--accept-stale"],
    "plan": ["--max-tasks", "--accept-risk", "--accept-stale"],
    "status": ["--all", "--task", "--ack"],
    "prompt": ["--tool", "--copy", "--out", "--fix", "--accept-stale"],
    "sync-context": ["--tool", "--check"],
    "verify": [
        "--commit", "--base", "--gate", "--override-ac", "--reason", "--accept-risk",
        "--accept-stale",
    ],
    "scan": ["--scanner", "--fail-on"],
    "task": ["--reason"],
    "run": ["--tool", "--timeout", "--budget", "--dry-run", "--accept-stale"],
    "build": [
        "--tool", "--parallel", "--max-retries", "--budget", "--timeout", "--only", "--dry-run",
        "--accept-stale",
    ],
    "merge": ["--into"],
    "auto": [
        "--yes", "--accept-risk", "--accept-stale", "--tool", "--parallel", "--max-retries",
        "--budget", "--timeout", "--only", "--dry-run",
    ],
}  # fmt: skip

GLOBAL_FLAGS = [
    "--project", "--json", "--no-color", "--non-interactive", "--yes", "--verbose",
    "--no-plugins", "--no-cache", "--trace", "--version",
]  # fmt: skip

V01_COMMANDS: dict[str, list[str]] = {
    "init": ["init"],
    "doctor": ["doctor"],
    "trust": ["trust"],
    "discover": ["discover"],
    "approve": ["approve", "prd"],
    "design": ["design"],
    "plan": ["plan"],
    "status": ["status"],
    "prompt": ["prompt", "T-001"],
    "sync-context": ["sync-context"],
}

LATER_COMMANDS: dict[str, tuple[list[str], str]] = {
    "verify": (["verify", "T-001"], "v0.2"),
    "scan": (["scan"], "v0.2"),
    "task": (["task", "show", "T-001"], "v0.2"),
    "run": (["run", "T-001"], "v0.3"),
    "build": (["build"], "v0.3"),
    "merge": (["merge"], "v0.3"),
    "auto": (["auto"], "v0.4"),
}


def test_command_tables_cover_every_command() -> None:
    assert set(V01_COMMANDS) | set(LATER_COMMANDS) == set(COMMAND_FLAGS)


def test_help_lists_every_command_and_global_flag() -> None:
    result = runner.invoke(app, ["--help"])
    assert result.exit_code == 0, result.output
    for command in COMMAND_FLAGS:
        assert command in result.stdout
    for flag in GLOBAL_FLAGS:
        assert flag in result.stdout


@pytest.mark.parametrize(("command", "flags"), sorted(COMMAND_FLAGS.items()))
def test_every_command_has_help_with_its_flags(command: str, flags: list[str]) -> None:
    result = runner.invoke(app, [command, "--help"])
    assert result.exit_code == 0, result.output
    assert result.stdout.startswith("Usage: ")
    for flag in flags:
        assert flag in result.stdout, f"{command} is missing {flag}"


def test_version() -> None:
    result = runner.invoke(app, ["--version"])
    assert result.exit_code == 0
    assert result.stdout == f"aipm {__version__}\n"


@pytest.mark.parametrize(("command", "case"), sorted(LATER_COMMANDS.items()))
def test_later_milestone_commands_say_when(command: str, case: tuple[list[str], str]) -> None:
    argv, milestone = case
    result = runner.invoke(app, argv)
    assert result.exit_code == 2
    assert f"aipm {command}: available in {milestone}" in result.stderr
    assert result.stdout == ""


# v0.1 commands whose build prompt has run (02: init, doctor, trust; 03: discover, approve).
# They have their own integration tests and no longer answer "not implemented yet".
BUILT = {"init", "doctor", "trust", "discover", "approve"}


@pytest.mark.parametrize(
    ("command", "argv"), sorted((c, a) for c, a in V01_COMMANDS.items() if c not in BUILT)
)
def test_v01_commands_exit_2_until_built(command: str, argv: list[str]) -> None:
    result = runner.invoke(app, argv)
    assert result.exit_code == 2
    assert f"aipm {command}: not implemented yet (build prompt" in result.stderr


@pytest.mark.parametrize("command", sorted(BUILT - {"doctor"}))
def test_built_commands_are_no_longer_stubs(command: str, tmp_path: Path) -> None:
    result = runner.invoke(app, ["-C", str(tmp_path), *V01_COMMANDS[command]])
    assert result.exit_code == 2
    assert "not implemented yet" not in result.stderr
    assert "is not inside a git repository" in result.stderr


def test_bare_aipm_exits_2_until_the_phase_engine_exists() -> None:
    result = runner.invoke(app, [])
    assert result.exit_code == 2
    assert "not implemented yet (build prompt 04)" in result.stderr


def test_json_envelope_for_a_stub_command() -> None:
    result = runner.invoke(app, ["--json", "verify", "T-001"])
    assert result.exit_code == 2
    assert result.stderr == ""
    lines = result.stdout.splitlines()
    assert len(lines) == 1, "--json prints exactly one object"
    env = json.loads(lines[0])
    assert set(env) == {"ok", "command", "version", "exit_code", "data", "errors"}
    assert env["ok"] is False
    assert env["command"] == "verify"
    assert env["version"] == __version__
    assert env["exit_code"] == 2
    assert env["data"] == {}
    assert len(env["errors"]) == 1
    error = env["errors"][0]
    assert set(error) == {"code", "message", "hint"}
    assert error["code"] == "NOT_AVAILABLE"
    assert error["message"] == "available in v0.2"


def test_approve_rejects_an_unknown_artifact() -> None:
    result = runner.invoke(app, ["approve", "everything"])
    assert result.exit_code == 2
    assert "everything" in result.stderr
