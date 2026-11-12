"""The clinic-booking example through v0.3 (build prompt 07): plan → trust → build → merge.

The stub agent writes T-002's hand-written implementation; the real build loop, gates, git and
journal run; only the LLM (FakeLLM) and the agent (the stub `claude`) are fakes.
"""

import json
from collections.abc import Callable
from pathlib import Path

import pytest

from aipm.llm.fake import FakeLLM
from tests.conftest import FakeSecrets, run_git
from tests.integration.build_flow import copy_t002, fake_registry, prepare_project, scenario
from tests.integration.conftest import UserDirs
from tests.integration.conftest import user_dirs as user_dirs  # noqa: PLC0414 - the fixture
from tests.integration.flow import aipm, ok

pytestmark = pytest.mark.usefixtures("allow_unix_sockets")


def test_v03_from_an_approved_plan_to_a_merged_task(
    tmp_repo: Path,
    fake_llm: Callable[[str], FakeLLM],
    fake_secrets: FakeSecrets,
    monkeypatch: pytest.MonkeyPatch,
    user_dirs: UserDirs,
) -> None:
    del fake_secrets
    fake_llm("clinic")
    fake_registry(monkeypatch)
    repo = prepare_project(tmp_repo, monkeypatch, user_dirs.home)
    scenario(user_dirs.home, {"T-002": [{"steps": copy_t002(), "cost": 0.4}]})

    dry = json.loads(ok(aipm(repo, "build", "--dry-run", flags=["--json"])).stdout)
    assert dry["data"]["batches"][0] == ["T-002"]

    built = json.loads(ok(aipm(repo, "build", "--only", "T-002", flags=["--json"])).stdout)
    assert built["data"]["tasks"][0]["status"] == "done"

    status = json.loads(ok(aipm(repo, "status", flags=["--json"])).stdout)["data"]
    assert status["spend"]["usd"] == pytest.approx(0.4)

    monkeypatch.setattr("aipm.cli.output.stdin_is_terminal", lambda: True)
    ok(aipm(repo, "merge", input="y\n"))
    assert run_git(repo, "rev-parse", "main") == run_git(repo, "rev-parse", "aipm/integration")
    assert "Aipm-Task: T-002" in run_git(repo, "log", "-1", "--format=%B", "main")
