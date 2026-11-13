"""Red-team v0.4, Part 3: what the whole-system run found in aipm itself (RT04-20).

The release and install findings (RT04-16 to RT04-19) are in `test_release_supply_chain.py`;
the hostile-world run is `tests/e2e/test_hostile_world.py`, which found this one.
"""

import json
from collections.abc import Callable, Iterator
from pathlib import Path

import pytest

from aipm.llm.fake import FakeLLM
from tests.conftest import FakeSecrets
from tests.integration.build_flow import copy_t002, fake_registry, prepare_project, scenario
from tests.integration.conftest import UserDirs
from tests.integration.conftest import user_dirs as user_dirs  # noqa: PLC0414 - the fixture
from tests.integration.flow import aipm, ok

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
