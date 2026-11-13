"""SECURITY.md §14.3 against every adapter's stub (build prompt 08): Codex, Gemini and Copilot.

The same malicious scenarios as `test_build_scenarios.py` (Claude Code) run end to end through
`aipm build --tool <tool>`, with each tool's stub asserting its own dispatch invariants (flags,
environment, worktree; `tests/fakes/bin/`). Copilot is render-only (ADR-0025): here its dispatch
is turned on to show the harness would hold it too, and one test checks it exits 8 otherwise.
None of these tools reports a cost, so every attempt is charged its task budget.
"""

import json
import os
import time
from collections.abc import Callable, Iterator
from dataclasses import replace
from pathlib import Path
from typing import Any

import pytest

from aipm.adapters import codex, copilot, gemini
from aipm.adapters._common import Detector
from aipm.domain.models import JournalEventType, RoleName, TaskStatus
from aipm.llm.fake import FakeLLM, FakeResponse
from tests.conftest import FakeSecrets, run_git
from tests.fakes.secrets import AGENT_KEYS
from tests.integration.build_flow import (
    FIXTURE,
    agent_stderr,
    calls,
    copy_t002,
    fake_registry,
    journal,
    prepare_project,
    scenario,
    status,
)
from tests.integration.conftest import (
    UserDirs,
    user_dirs,  # noqa: F401 - an autouse fixture
)
from tests.integration.flow import aipm, planned, reply, trust
from tests.integration.test_verify_cli import STUBS, install, use_test_gates

pytestmark = pytest.mark.usefixtures("allow_unix_sockets")
SLOTS = FIXTURE / "T-002" / "tests" / "booking" / "test_slots.py.txt"
TOOLS = ["codex", "gemini", "copilot"]
PLANTED = {
    "codex": ("config.toml", 'approval_policy = "on-request"\n'),
    "gemini": (".gemini/settings.json", '{"tools": {"allowed": ["run_shell_command"]}}'),
    "copilot": ("config.json", '{"trustedFolders": ["/"]}'),
}
"""Per tool, a file in its isolated config home that would widen its next run."""
GLOBAL = {"codex": ".codex/config.toml", "gemini": ".gemini/settings.json",
          "copilot": ".copilot/config.json"}  # fmt: skip


@pytest.fixture(params=TOOLS)
def tool(request: pytest.FixtureRequest, monkeypatch: pytest.MonkeyPatch) -> str:
    name: str = request.param
    for module in (codex, copilot, gemini):
        module.DETECTOR.clear()
    monkeypatch.setattr(
        copilot.CopilotAdapter, "detector", Detector(replace(copilot.DETECT, unverified=()))
    )
    key, value = AGENT_KEYS[name]
    monkeypatch.setenv(key, value)
    return name


@pytest.fixture
def dirs(user_dirs: UserDirs) -> UserDirs:  # noqa: F811 - the imported fixture
    return user_dirs


@pytest.fixture(autouse=True)
def registry(monkeypatch: pytest.MonkeyPatch) -> None:
    fake_registry(monkeypatch)


@pytest.fixture
def project(
    tmp_repo: Path,
    fake_llm: Callable[[str], FakeLLM],
    fake_secrets: FakeSecrets,
    monkeypatch: pytest.MonkeyPatch,
    dirs: UserDirs,
) -> Path:
    del fake_secrets
    fake_llm("clinic")
    return prepare_project(tmp_repo, monkeypatch, dirs.home)


@pytest.fixture(autouse=True)
def no_broken_invariant(request: pytest.FixtureRequest) -> Iterator[None]:
    repo: Path | None = (
        request.getfixturevalue("project") if "project" in request.fixturenames else None
    )
    yield
    if repo is not None:
        assert "STUB-ASSERTION-FAILED" not in agent_stderr(repo)


def build(repo: Path, tool: str, *args: str) -> tuple[int, dict[str, Any]]:
    result = aipm(repo, "build", "--tool", tool, *args, flags=["--json"])
    return result.exit_code, json.loads(result.stdout)


def tool_calls(home: Path, tool: str) -> list[dict[str, Any]]:
    found = [c for c in calls(home) if c.get("tool") == tool]
    assert len(found) == len(calls(home)), "another stub agent was started"
    return found


def assert_severe(
    repo: Path, home: Path, tool: str, code: int, envelope: dict[str, Any], kind: str
) -> None:
    """Blocked at once (exit 6), never retried, recorded, nothing merged."""
    assert code == 6, envelope
    assert len(tool_calls(home, tool)) == 1, "a severe violation is never retried"
    (outcome,) = envelope["data"]["tasks"]
    assert (outcome["status"], outcome["reason"]) == ("blocked", "policy_violation")
    assert status(repo, "T-002") is TaskStatus.BLOCKED
    run = journal(repo, envelope["data"]["run_id"])
    kinds = {e.data.get("kind") for e in run if e.type is JournalEventType.POLICY_VIOLATION}
    assert kind in kinds, kinds
    assert not any(e.type is JournalEventType.GATE_RESULT for e in run), "no gate runs"
    assert run_git(repo, "rev-parse", "aipm/integration") == run_git(repo, "rev-parse", "main")


# ---------------------------------------------------------------- severe


def test_a_clean_attempt_passes_and_secrets_never_reach_the_agent(
    project: Path, dirs: UserDirs, tool: str
) -> None:
    scenario(dirs.home, {"T-002": [{"steps": copy_t002()}]})
    code, envelope = build(project, tool, "--only", "T-002")
    assert code == 0, envelope
    (call,) = tool_calls(dirs.home, tool)
    assert "aipm/worktrees/" in call["cwd"]
    assert envelope["data"]["spent_usd"] == pytest.approx(2.0)  # no cost reported: the cap


def test_editing_a_test_it_does_not_own_is_severe(project: Path, dirs: UserDirs, tool: str) -> None:
    steps = [*copy_t002(), {"write": "tests/api/test_otp.py", "text": "def test_x():\n    pass\n"}]
    scenario(dirs.home, {"T-002": [{"steps": steps}]})
    code, envelope = build(project, tool, "--only", "T-002")
    assert_severe(project, dirs.home, tool, code, envelope, "test_not_owned")


def test_writing_pm_tasks_yaml_is_severe(project: Path, dirs: UserDirs, tool: str) -> None:
    steps = [*copy_t002(), {"write": ".pm/tasks.yaml", "text": "schema_version: 1\ntasks: []\n"}]
    scenario(dirs.home, {"T-002": [{"steps": steps}]})
    code, envelope = build(project, tool, "--only", "T-002")
    assert_severe(project, dirs.home, tool, code, envelope, "protected_path")


def test_a_pre_commit_hook_is_severe_and_never_runs(
    project: Path, dirs: UserDirs, tool: str, tmp_path: Path
) -> None:
    marker = tmp_path / "hook-ran"
    hook = {"git_hook": "pre-commit", "text": f"#!/bin/sh\necho ran > '{marker}'\n"}
    scenario(dirs.home, {"T-002": [{"steps": [*copy_t002(), hook]}]})
    code, envelope = build(project, tool, "--only", "T-002")
    assert_severe(project, dirs.home, tool, code, envelope, "git_integrity")
    assert not marker.exists()


def test_core_fsmonitor_is_severe_and_never_runs(
    project: Path, dirs: UserDirs, tool: str, tmp_path: Path
) -> None:
    marker = tmp_path / "fsmonitor-ran"
    monitor = tmp_path / "monitor"
    monitor.write_text(f"#!/bin/sh\necho ran > '{marker}'\n", encoding="utf-8")
    monitor.chmod(0o755)
    setting = {"git_config": f"[core]\n\tfsmonitor = {monitor}\n"}
    scenario(dirs.home, {"T-002": [{"steps": [*copy_t002(), setting]}]})
    code, envelope = build(project, tool, "--only", "T-002")
    assert_severe(project, dirs.home, tool, code, envelope, "git_integrity")
    assert not marker.exists()


def test_a_symlink_to_ssh_is_severe(project: Path, dirs: UserDirs, tool: str) -> None:
    (dirs.home / ".ssh").mkdir()
    link = {"symlink": "src/clinic/booking/keys", "to": str(dirs.home / ".ssh")}
    scenario(dirs.home, {"T-002": [{"steps": [*copy_t002(), link]}]})
    code, envelope = build(project, tool, "--only", "T-002")
    assert_severe(project, dirs.home, tool, code, envelope, "symlink")


def test_changing_the_global_agent_config_is_severe(
    project: Path, dirs: UserDirs, tool: str
) -> None:
    write = {"home_write": GLOBAL[tool], "text": "planted\n"}
    scenario(dirs.home, {"T-002": [{"steps": [*copy_t002(), write]}]})
    code, envelope = build(project, tool, "--only", "T-002")
    assert_severe(project, dirs.home, tool, code, envelope, "git_integrity")


def test_planting_settings_in_the_isolated_config_home_is_severe(
    project: Path, dirs: UserDirs, tool: str
) -> None:
    rel, text = PLANTED[tool]
    scenario(dirs.home, {"T-002": [{"steps": [*copy_t002(), {"config_home_write": rel,
                                                              "text": text}]}]})  # fmt: skip
    code, envelope = build(project, tool, "--only", "T-002")
    assert_severe(project, dirs.home, tool, code, envelope, "git_integrity")
    env_var = {"codex": "CODEX_HOME", "gemini": "GEMINI_CLI_HOME", "copilot": "COPILOT_HOME"}
    assert env_var[tool] in envelope["data"]["tasks"][0]["detail"]


# ---------------------------------------------------------------- failed and retried


def test_a_skip_marker_fails_the_attempt_and_is_reverted(
    project: Path, dirs: UserDirs, tool: str
) -> None:
    skipped = SLOTS.read_text(encoding="utf-8").replace(
        "def test_a_taken_slot_fails", "@pytest.mark.skip\ndef test_a_taken_slot_fails"
    )
    tamper = [*copy_t002(), {"write": "tests/booking/test_slots.py", "text": skipped}]
    scenario(dirs.home, {"T-002": [{"steps": tamper}, {"steps": copy_t002()}]})
    code, envelope = build(project, tool, "--only", "T-002")
    assert code == 0, envelope
    assert len(tool_calls(dirs.home, tool)) == 2
    merged = run_git(project, "show", "aipm/integration:tests/booking/test_slots.py")
    assert "mark.skip" not in merged


def test_an_undeclared_dependency_is_reverted_and_retried(
    project: Path, dirs: UserDirs, tool: str
) -> None:
    base = (project / "pyproject.toml").read_text(encoding="utf-8")
    added = base.replace("dependencies = []", 'dependencies = ["requests"]')
    sneaky = [*copy_t002(), {"write": "pyproject.toml", "text": added}]
    scenario(dirs.home, {"T-002": [{"steps": sneaky}, {"steps": copy_t002()}]})
    code, envelope = build(project, tool, "--only", "T-002")
    assert code == 0, envelope
    assert len(tool_calls(dirs.home, tool)) == 2
    assert run_git(project, "show", "aipm/integration:pyproject.toml") == base


def test_aipm_done_is_ignored(project: Path, dirs: UserDirs, tool: str) -> None:
    scenario(dirs.home, {"T-002": [{"text": "All checks pass.\nAIPM-DONE"}]})
    code, envelope = build(project, tool, "--only", "T-002", "--max-retries", "1")
    assert code == 3, envelope
    (outcome,) = envelope["data"]["tasks"]
    assert (outcome["status"], outcome["reason"]) == ("blocked", "gates_failed")


def test_a_typosquatted_declared_dependency_fails_the_deps_gate(
    tmp_repo: Path,
    fake_llm: Callable[[str], FakeLLM],
    fake_secrets: FakeSecrets,
    monkeypatch: pytest.MonkeyPatch,
    dirs: UserDirs,
    tool: str,
) -> None:
    del fake_secrets
    llm = fake_llm("clinic")
    monkeypatch.setenv("PATH", f"{STUBS}{os.pathsep}{os.environ['PATH']}")
    (dirs.home / ".gitconfig").write_text(
        "[user]\n\tname = aipm owner\n\temail = owner@example.invalid\n", encoding="utf-8"
    )
    plan = reply("planner")
    plan["tasks"][0]["deps_add"] = [{"ecosystem": "pypi", "name": "reqeusts"}]
    llm._queues[RoleName.PLANNER] = [FakeResponse.model_validate({"json": plan})]  # pyright: ignore[reportPrivateUsage]
    planned(tmp_repo)
    use_test_gates(tmp_repo)
    install(FIXTURE / "base", tmp_repo)
    run_git(tmp_repo, "add", "-A", "--", ".", ":!.pm")
    run_git(tmp_repo, "commit", "-q", "-m", "base")
    trust(tmp_repo)
    dirs.config.write_text("schema_version: 1\ndispatch: {fail_fast: false}\n")
    text = (tmp_repo / "pyproject.toml").read_text("utf-8")
    squat = text.replace("dependencies = []", 'dependencies = ["reqeusts>=2"]')
    scenario(dirs.home, {"T-001": [{"steps": [{"write": "pyproject.toml", "text": squat}]}]})
    code, envelope = build(tmp_repo, tool, "--only", "T-001", "--max-retries", "1")
    assert code == 3, envelope
    run_id = envelope["data"]["run_id"]
    report = (tmp_repo / ".pm/runs" / run_id / "gates/T-001/1/report.yaml").read_text()
    assert "reqeusts is one edit from requests" in report
    assert "STUB-ASSERTION-FAILED" not in agent_stderr(tmp_repo)


# ---------------------------------------------------------------- killed and capped


def test_an_agent_past_its_timeout_is_killed(project: Path, dirs: UserDirs, tool: str) -> None:
    scenario(dirs.home, {"T-002": [{"steps": [{"sleep": 60}]}]})
    started = time.monotonic()
    code, envelope = build(
        project, tool, "--only", "T-002", "--timeout", "2s", "--max-retries", "1"
    )
    assert time.monotonic() - started < 30
    assert code == 3, envelope
    (outcome,) = envelope["data"]["tasks"]
    assert (outcome["status"], outcome["reason"]) == ("blocked", "timeout")


def test_a_forked_daemon_dies_with_the_process_group(
    project: Path, dirs: UserDirs, tool: str, tmp_path: Path
) -> None:
    pid_file = tmp_path / "daemon.pid"
    scenario(dirs.home, {"T-002": [{"steps": [{"daemon": str(pid_file)}, *copy_t002()]}]})
    code, envelope = build(project, tool, "--only", "T-002")
    assert code == 0, envelope
    pid = int(pid_file.read_text(encoding="utf-8"))
    deadline = time.monotonic() + 10
    while time.monotonic() < deadline:
        try:
            os.kill(pid, 0)
        except ProcessLookupError:
            break
        time.sleep(0.05)
    else:
        raise AssertionError(f"the daemon {pid} outlived the agent")


def test_fifty_megabytes_of_output_are_capped(project: Path, dirs: UserDirs, tool: str) -> None:
    scenario(dirs.home, {"T-002": [{"steps": [{"flood_mb": 50}, *copy_t002()]}]})
    code, envelope = build(project, tool, "--only", "T-002")
    assert code == 0, envelope
    agent = project / ".pm" / "runs" / envelope["data"]["run_id"] / "agent" / "T-002" / "1"
    assert (agent / "stdout.jsonl").stat().st_size < 2_200_000
    result = json.loads((agent / "result.json").read_text(encoding="utf-8"))
    assert result["output_dropped_bytes"] > 40_000_000
    assert result["saw_result"] is False


# ---------------------------------------------------------------- tool-specific


def test_gemini_refuses_a_repository_with_gemini_settings(
    project: Path, dirs: UserDirs, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A committed `.gemini/settings.json` would give Gemini MCP servers, hooks or wider tool
    rules: the build stops with exit 6 before the agent starts."""
    key, value = AGENT_KEYS["gemini"]
    monkeypatch.setenv(key, value)
    gemini.DETECTOR.clear()
    (project / ".gemini").mkdir()
    (project / ".gemini" / "settings.json").write_text('{"mcpServers": {}}\n', encoding="utf-8")
    run_git(project, "add", ".gemini/settings.json")
    run_git(project, "commit", "-q", "-m", "gemini settings")
    scenario(dirs.home, {"T-002": [{"steps": copy_t002()}]})
    code, envelope = build(project, "gemini", "--only", "T-002")
    assert code == 6, envelope
    assert calls(dirs.home) == []
    assert ".gemini" in json.dumps(envelope)


def test_copilot_dispatch_stays_off(
    project: Path, dirs: UserDirs, monkeypatch: pytest.MonkeyPatch
) -> None:
    """ADR-0025: without the test switch, `build --tool copilot` exits 8 and names why."""
    key, value = AGENT_KEYS["copilot"]
    monkeypatch.setenv(key, value)
    copilot.DETECTOR.clear()
    scenario(dirs.home, {"T-002": [{"steps": copy_t002()}]})
    code, envelope = build(project, "copilot", "--only", "T-002")
    assert code == 8, envelope
    assert "unverified" in json.dumps(envelope)
    assert calls(dirs.home) == []
