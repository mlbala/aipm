"""The v0.4 security red-team pass, part 1: the new coding-agent surfaces (build prompt 09 v0.4;
docs/security/reviews/v0.4-progress.md).

One section per finding (RT04-n). Every test in a finding section failed before its fix. The
"held" sections pin controls the pass attacked without breaking them. The end-to-end tests run
`aipm build --tool <tool>` on the clinic example with the stub agents in `tests/fakes/bin/`.
"""

import json
from collections.abc import Callable, Iterator
from pathlib import Path
from typing import Any

import pytest
from ruamel.yaml import YAML

from aipm.adapters import codex, copilot, gemini
from aipm.adapters.base import AgentResult
from aipm.adapters.claude_code import ClaudeCodeAdapter
from aipm.adapters.codex import CodexAdapter
from aipm.adapters.gemini import GeminiAdapter
from aipm.execution.process import ProcessResult
from aipm.llm.fake import FakeLLM
from tests.conftest import FakeSecrets
from tests.fakes.secrets import AGENT_KEYS
from tests.integration.build_flow import (
    agent_stderr,
    copy_t002,
    fake_registry,
    prepare_project,
    scenario,
)
from tests.integration.conftest import (
    UserDirs,
    user_dirs,  # noqa: F401 - an autouse fixture
)
from tests.integration.flow import aipm

pytestmark = pytest.mark.usefixtures("allow_unix_sockets")
CORPUS = Path(__file__).parent / "corpus"
TOOLS = ["codex", "gemini"]
"""The dispatchable tools v0.4 adds (Copilot is render-only, ADR-0025)."""


@pytest.fixture
def dirs(user_dirs: UserDirs) -> UserDirs:  # noqa: F811 - the imported fixture
    return user_dirs


@pytest.fixture(autouse=True)
def registry(monkeypatch: pytest.MonkeyPatch) -> None:
    fake_registry(monkeypatch)


@pytest.fixture(params=TOOLS)
def tool(request: pytest.FixtureRequest, monkeypatch: pytest.MonkeyPatch) -> str:
    name: str = request.param
    for module in (codex, copilot, gemini):
        module.DETECTOR.clear()
    key, value = AGENT_KEYS[name]
    monkeypatch.setenv(key, value)
    return name


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


def case_text(case_id: str) -> str:
    (path,) = CORPUS.glob(f"{case_id}-*.yaml")
    data: dict[str, Any] = YAML(typ="safe", pure=True).load(path.read_text(encoding="utf-8"))
    return str(data["input"]["text"])


def output(stdout: bytes, *, code: int = 0) -> ProcessResult:
    return ProcessResult(("agent",), code, stdout, b"", timed_out=False, truncated=False,
                         duration_s=1.0)  # fmt: skip


# ---------------------------------------------------------------- RT04-1: nested JSON


def deep(key: str = "type", depth: int = 100_000) -> bytes:
    """One JSON object line nested deeper than Python's recursion limit."""
    return b'{"' + key.encode() + b'": "result", "x": ' + b"[" * depth + b"]" * depth + b"}"


@pytest.mark.parametrize(
    "adapter", [CodexAdapter(), GeminiAdapter(), ClaudeCodeAdapter()], ids=lambda a: a.name.value
)
def test_deeply_nested_json_in_agent_output_parses_as_no_result(adapter: Any) -> None:
    """`json.loads` raises `RecursionError`, which is not a `ValueError`: it escaped every
    adapter's `parse_result`, crashed the build and left the attempt charged nothing."""
    result: AgentResult = adapter.parse_result(output(deep() + b"\n"))
    assert result.cost_usd is None
    assert result.blocked_question is None


def test_deeply_nested_json_is_charged_the_task_budget(
    project: Path, dirs: UserDirs, tool: str
) -> None:
    line = deep(depth=200_000).decode()
    scenario(dirs.home, {"T-002": [{"steps": [*copy_t002(), {"raw_stdout": line}]}]})
    code, envelope = build(project, tool, "--only", "T-002")
    assert code == 0, envelope
    assert envelope["data"]["spent_usd"] == pytest.approx(2.0)


def test_c056_nested_agent_output_is_data() -> None:
    start = case_text("C-056").strip()
    raw = (start + "[" * 100_000 + "]" * 100_001 + "}").encode()
    for adapter in (CodexAdapter(), GeminiAdapter(), ClaudeCodeAdapter()):
        result = adapter.parse_result(output(raw + b"\n"))
        assert (result.cost_usd, result.blocked_question) == (None, None)
