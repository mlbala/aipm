"""Red-team v0.4, Part 3: what the whole-system run and CI found in aipm itself (RT04-20,
RT04-21).

The release and install findings (RT04-16 to RT04-19) are in `test_release_supply_chain.py`;
the hostile-world run is `tests/e2e/test_hostile_world.py`, which found this one.
"""

import hashlib
import json
from collections.abc import Callable, Iterator
from pathlib import Path
from typing import Any

import pytest

from aipm.adapters.claude_code import ClaudeCodeAdapter
from aipm.adapters.codex import CodexAdapter
from aipm.adapters.gemini import GeminiAdapter
from aipm.gates.reports import ReportError, parse_jest
from aipm.llm.fake import FakeLLM
from aipm.scanners import registry
from aipm.scanners.registry import RegistryError
from aipm.security import diff_checks, json_limits
from aipm.security.json_limits import MAX_DEPTH, TooDeep, depth, loads_bounded
from aipm.state.trust_store import repo_agent_config
from tests.conftest import FakeSecrets
from tests.integration.build_flow import copy_t002, fake_registry, prepare_project, scenario
from tests.integration.conftest import UserDirs
from tests.integration.conftest import user_dirs as user_dirs  # noqa: PLC0414 - the fixture
from tests.integration.flow import aipm, ok
from tests.security.test_dispatch_surface import bare_off
from tests.security.test_redteam_v04 import output

pytestmark = pytest.mark.usefixtures("allow_unix_sockets")


@pytest.fixture
def project(
    tmp_repo: Path,
    fake_llm: Callable[[str], FakeLLM],
    fake_secrets: FakeSecrets,
    monkeypatch: pytest.MonkeyPatch,
    user_dirs: UserDirs,
) -> Path:
    del fake_secrets
    fake_llm("clinic")
    fake_registry(monkeypatch)
    return prepare_project(tmp_repo, monkeypatch, user_dirs.home)


@pytest.fixture
def same_minute(monkeypatch: pytest.MonkeyPatch) -> Iterator[None]:
    """Two builds started in one minute, the newer with the smaller random suffix: run IDs
    name only the minute (`r-YYYYMMDD-HHMM-xxxx`)."""
    ids = iter(["r-20261113-1200-ffff", "r-20261113-1200-0000"])
    monkeypatch.setattr("aipm.app.build_loop.new_run_id", lambda: next(ids))
    yield


def test_status_shows_the_newest_builds_spend_when_two_start_in_one_minute(
    project: Path, user_dirs: UserDirs, same_minute: None
) -> None:
    """RT04-20: `aipm status` took the newest build by run ID, so of two builds started in
    one minute it showed whichever had the larger random suffix: here the older one's $0.30,
    not the newest's $0.70 (the hostile-world run saw $0.00 for a build that spent $4.00).
    Resume already ordered runs by their `run_started` time."""
    del same_minute
    scenario(user_dirs.home, {"T-002": [{"text": "AIPM-DONE", "cost": 0.3},
                                        {"steps": copy_t002(), "cost": 0.7}]})  # fmt: skip
    first = aipm(project, "build", "--only", "T-002", "--max-retries", "1", flags=["--json"])
    assert first.exit_code == 3, first.output
    ok(aipm(project, "task", "reset", "T-002", "--reason", "try again"))
    ok(aipm(project, "build", "--only", "T-002", flags=["--json"]))

    spend = json.loads(ok(aipm(project, "status", flags=["--json"])).stdout)["data"]["spend"]
    assert spend["run_id"] == "r-20261113-1200-0000"
    assert spend["usd"] == pytest.approx(0.7)


# ---------------------------------------------------------------- RT04-21: deep JSON on 3.14

DEEPER = MAX_DEPTH + 44
"""300: deeper than aipm's limit, and well inside what `json.loads` parses on Python 3.13 and
3.14 alike, so these tests show aipm's own check, not the interpreter's recursion limit."""


def nested(depth: int, start: str = "") -> str:
    return start + "[" * depth + "]" * depth + ("}" if start else "")


def test_depth_counts_brackets_outside_strings_only() -> None:
    assert depth('{"a": "[[[{", "b": [1, {"c": []}]}') == 4
    assert depth('{"a": "\\"[[", "b": "\\\\"}') == 1
    assert depth('{"a": "[[[') == 1  # an unterminated string runs to the end
    assert depth(nested(MAX_DEPTH)) == MAX_DEPTH


def test_loads_bounded_refuses_json_deeper_than_the_limit_on_every_python(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """RT04-21: Python 3.14 parses JSON nested 100,000 deep, where 3.13 raised RecursionError,
    which the RT04-1 and RT04-10 readers relied on: on 3.14 a deep agent result line became a
    result, and a deep repository `.mcp.json` became surface content."""
    assert loads_bounded(nested(MAX_DEPTH)) == json.loads(nested(MAX_DEPTH))
    for data in (nested(DEEPER), nested(DEEPER).encode(), nested(DEEPER).encode("utf-16")):
        with pytest.raises(TooDeep):
            loads_bounded(data)
    assert issubclass(TooDeep, ValueError)

    def recursion(*_: object, **__: object) -> object:
        raise RecursionError

    monkeypatch.setattr("aipm.security.json_limits.json.loads", recursion)
    with pytest.raises(TooDeep):
        loads_bounded("[]")


@pytest.mark.parametrize("adapter", [CodexAdapter(), GeminiAdapter(), ClaudeCodeAdapter()],
                         ids=lambda a: a.name.value)  # fmt: skip
def test_a_result_line_deeper_than_the_limit_is_no_result(adapter: Any) -> None:
    """C-056 at a depth every Python parses: a result event that also nests deeper than the
    limit is broken output, never a result or a cost."""
    start = '{"type": "result", "total_cost_usd": 0.0, "result": "x", "response": "x", "x": '
    line = nested(DEEPER, start).encode()
    result = adapter.parse_result(output(line + b"\n"))
    assert (result.cost_usd, result.blocked_question) == (None, None)


@pytest.mark.parametrize("name", [".mcp.json", ".claude/settings.json"])
def test_a_repository_agent_file_deeper_than_the_limit_is_pinned_by_hash(
    tmp_path: Path, name: str
) -> None:
    repo = tmp_path / "repo"
    (repo / ".claude").mkdir(parents=True)
    text = nested(DEEPER, '{"mcpServers": ')
    (repo / name).write_text(text, encoding="utf-8")
    agent = repo_agent_config(repo, bare_off())  # type: ignore[arg-type]
    assert agent is not None
    assert agent[name] == {"sha256": hashlib.sha256(text.encode()).hexdigest(),
                           "error": "nested too deeply to show"}  # fmt: skip


def test_registry_answers_test_reports_and_tool_config_deeper_than_the_limit_are_unreadable() -> (
    None
):
    deep = nested(DEEPER, '{"x": ')
    with pytest.raises(RegistryError):
        registry._json_object(registry.Response(200, deep.encode()))  # pyright: ignore[reportPrivateUsage]
    with pytest.raises(ReportError):
        parse_jest(nested(DEEPER, '{"testResults": ').encode())
    assert diff_checks._json(deep) is None  # pyright: ignore[reportPrivateUsage]


def test_only_the_bounded_loader_parses_json_with_the_standard_library() -> None:
    """Every reader goes through `loads_bounded`; `llm/structured.py` checks the depth itself
    (64 levels) before its own `json.loads` with hooks. pydantic's parser has its own limit."""
    src = Path(json_limits.__file__).parents[1]
    allowed = {src / "security" / "json_limits.py", src / "llm" / "structured.py"}
    for path in sorted(src.rglob("*.py")):
        if path not in allowed:
            assert "json.loads(" not in path.read_text(encoding="utf-8"), path
