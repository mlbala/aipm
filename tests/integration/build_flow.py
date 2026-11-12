"""Helpers for the build tests: the clinic project ready to build, and the stub agent's script.

The stub `claude` (`tests/fakes/bin/claude`) reads `$HOME/.stub-claude/scenario.json` and logs
every call to `calls.jsonl` there; `STUB-ASSERTION-FAILED` on its stderr means aipm broke a
dispatch invariant, which every test checks never happens.
"""

import json
import os
from collections.abc import Mapping
from pathlib import Path
from typing import TYPE_CHECKING, Any

import pytest

from aipm.adapters import claude_code
from aipm.domain.models import JournalEvent, TaskStatus
from aipm.scanners.registry import Response
from tests.conftest import run_git
from tests.integration.flow import aipm, ok, planned, tasks, trust

if TYPE_CHECKING:
    from aipm.execution.process import ProcessResult

REPO_ROOT = Path(__file__).resolve().parents[2]
FIXTURE = REPO_ROOT / "tests" / "fakes" / "clinic"
T002_FILES = {
    "src/clinic/booking/__init__.py": FIXTURE / "T-002/src/clinic/booking/__init__.py.txt",
    "src/clinic/booking/service.py": FIXTURE / "T-002/src/clinic/booking/service.py.txt",
    "tests/booking/test_slots.py": FIXTURE / "T-002/tests/booking/test_slots.py.txt",
}


def copy_t002() -> list[dict[str, Any]]:
    """Steps that write the good T-002 implementation."""
    return [{"copy": rel, "from": str(src)} for rel, src in T002_FILES.items()]


def module_and_test(
    task: str, module: str, test_dir: str, *, ok: bool = True
) -> list[dict[str, Any]]:
    """Steps that write a small module and a passing (or failing) test naming the task's AC."""
    number = task.removeprefix("T-")
    body = "def value() -> int:\n    return 1\n"
    check = "1" if ok else "2"
    dotted = module.replace("/", ".").removesuffix(".py").removeprefix("src.")
    test = (
        f"from {dotted} import value\n\n\n"
        f"def test_ac_t{number}_1() -> None:\n"
        f'    """AC-T{number}-1"""\n'
        f"    assert value() == {check}\n"
    )
    return [
        {"write": module, "text": body},
        {"write": f"{test_dir}/test_{task.lower().replace('-', '_')}.py", "text": test},
    ]


def scenario(home: Path, tasks_plan: dict[str, list[dict[str, Any]]], **extra: Any) -> None:
    """Write the stub agent's scenario: per task, one entry per call."""
    stub = home / ".stub-claude"
    stub.mkdir(parents=True, exist_ok=True)
    (stub / "scenario.json").write_text(
        json.dumps({"tasks": tasks_plan, **extra}), encoding="utf-8"
    )


def calls(home: Path) -> list[dict[str, Any]]:
    """Every dispatch the stub saw."""
    log = home / ".stub-claude" / "calls.jsonl"
    if not log.exists():
        return []
    return [json.loads(line) for line in log.read_text(encoding="utf-8").splitlines()]


def journal(repo: Path, run_id: str) -> list[JournalEvent]:
    path = repo / ".pm" / "runs" / run_id / "journal.jsonl"
    return [JournalEvent.model_validate_json(line) for line in path.read_text().splitlines()]


def status(repo: Path, task_id: str) -> TaskStatus:
    return next(t.status for t in tasks(repo).tasks if t.id == task_id)


def agent_stderr(repo: Path) -> str:
    """Every agent stderr saved in every run, joined."""
    return "\n".join(
        p.read_text(encoding="utf-8", errors="replace")
        for p in (repo / ".pm" / "runs").rglob("stderr.txt")
    )


def fake_registry(monkeypatch: pytest.MonkeyPatch) -> None:
    """Every package exists and was first released in 2015 (no network in tests)."""

    def fetch(url: str, headers: Mapping[str, str]) -> Response:
        del url, headers
        body = {"files": [{"upload-time": "2015-01-01T00:00:00Z"}],
                "time": {"created": "2015-01-01T00:00:00Z"}}  # fmt: skip
        return Response(200, json.dumps(body).encode())

    monkeypatch.setattr("aipm.scanners.registry._fetch", fetch)


def prepare_project(repo: Path, monkeypatch: pytest.MonkeyPatch, home: Path) -> Path:
    """The clinic project planned and trusted, with test gates and T-001 skipped (FakeLLM and
    the fake secrets must already be in place)."""
    from tests.integration.test_verify_cli import STUBS, install, use_test_gates  # noqa: PLC0415

    claude_code._detected.clear()  # pyright: ignore[reportPrivateUsage] - one CLI run per process
    monkeypatch.setenv("PATH", f"{STUBS}{os.pathsep}{os.environ['PATH']}")
    (home / ".gitconfig").write_text(
        "[user]\n\tname = aipm owner\n\temail = owner@example.invalid\n", encoding="utf-8"
    )
    planned(repo)
    use_test_gates(repo)
    install(FIXTURE / "base", repo)
    run_git(repo, "add", "-A", "--", ".", ":!.pm")
    run_git(repo, "commit", "-q", "-m", "base")
    trust(repo)
    ok(aipm(repo, "task", "skip", "T-001", "--reason", "built by hand"))
    return repo


def without_ac_review(repo: Path) -> None:
    """Drop the optional AC reviewer from the menu (no FakeLLM in a subprocess), and trust."""
    from tests.integration.test_verify_cli import edit_config  # noqa: PLC0415

    def change(layer: dict[str, object]) -> None:
        gates = dict(layer["gates"])  # type: ignore[call-overload]
        gates.pop("ac_review", None)
        layer["gates"] = gates

    edit_config(repo, change)
    trust(repo)


def package_steps(
    repo: Path, task_id: str, package: str, test_file: str, *, blocking: bool = False
) -> list[dict[str, Any]]:
    """Steps that write `src/clinic/<package>/` and a test naming every acceptance criterion of
    the task. A `blocking` test writes `$HOME/.stub-claude/in-gates`, waits while `hold` exists
    there, then writes `gates-done`: a test can stop aipm in the middle of the gates."""
    task = next(t for t in tasks(repo).tasks if t.id == task_id)
    ids = " ".join(c.id for c in task.acceptance)
    module = f'"""{task_id}."""\n\n\ndef value() -> int:\n    """Return one."""\n    return 1\n'
    wait = (
        '    stub = Path.home() / ".stub-claude"\n'
        '    (stub / "in-gates").write_text("yes", encoding="utf-8")\n'
        "    deadline = time.monotonic() + LIMIT_S\n"
        '    while (stub / "hold").exists() and time.monotonic() < deadline:\n'
        "        time.sleep(PAUSE_S)\n"
        '    (stub / "gates-done").write_text("yes", encoding="utf-8")\n'
    )
    head = (
        f'"""{task_id} tests."""\n\nimport time\nfrom pathlib import Path\n\n'
        f"from clinic.{package}.core import value\n\nLIMIT_S = 120\nPAUSE_S = 0.1\n\n\n"
        if blocking
        else f'"""{task_id} tests."""\n\nfrom clinic.{package}.core import value\n\n\n'
    )
    test = (
        head
        + "def test_value() -> None:\n"
        + f'    """{ids}: the value is one."""\n'
        + (wait if blocking else "")
        + "    assert value() == 1\n"
    )
    return [
        {"write": f"src/clinic/{package}/__init__.py", "text": f'"""{package}."""\n'},
        {"write": f"src/clinic/{package}/core.py", "text": module},
        {"write": test_file, "text": test},
    ]


def run_aipm_process(repo: Path, *args: str, timeout_s: float = 300) -> "ProcessResult":
    """aipm as a real process (`python -m aipm`), through aipm's own `run_safe`, so a test can
    kill it (`running_groups()` names it). Network goes to a closed port."""
    import sys  # noqa: PLC0415

    from aipm.execution.process import build_env, run_safe  # noqa: PLC0415

    argv = [sys.executable, "-m", "aipm", "--non-interactive", "--json", "-C", str(repo), *args]
    closed = "http://127.0.0.1:9"
    env = build_env(list(os.environ), extra={"HTTPS_PROXY": closed, "HTTP_PROXY": closed})
    return run_safe(argv, cwd=repo, env=env, timeout_s=timeout_s, max_output_bytes=4_000_000)


def task_commits(repo: Path, branch: str = "aipm/integration") -> list[str]:
    """The `Aipm-Task` trailer of every commit on `branch`, newest first."""
    out = run_git(repo, "log", "--format=%(trailers:key=Aipm-Task,valueonly)%x00", branch)
    return [part.strip() for part in out.split("\0") if part.strip()]
