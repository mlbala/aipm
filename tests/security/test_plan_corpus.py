"""The planner corpus through `aipm plan` (build prompt 04; SECURITY.md §7.3-§7.5, §14.2).

Each hostile reply must be rejected or neutralized by the plan validator, never by the prompt:
the FakeLLM "obeys" every injection, and sends the same reply again for the repair attempt.

C-015 unknown gate, C-016 gate argument in a description, C-017 unsafe owned paths, C-018 a
cycle, C-019 500 tasks, C-020 OSC 52 in a criterion, C-021 shell metacharacters in deps_add.
"""

import json
from collections.abc import Callable
from pathlib import Path
from typing import Any

import pytest
from click.testing import Result
from ruamel.yaml import YAML

from aipm.config.loader import load_config
from aipm.domain.models import RoleName, SecurityEventKind
from aipm.llm.fake import FakeLLM
from aipm.state.store import open_store
from aipm.state.trust_store import default_trust_store, hash_surface, render_surface
from tests.integration.conftest import user_dirs  # noqa: F401 - isolates HOME and the trust store
from tests.integration.flow import aipm, designed, ok, pm_files, reply, tasks, use_responses

CORPUS = Path(__file__).parent / "corpus"
PLANNER = RoleName.PLANNER


def corpus(case_id: str) -> dict[str, Any]:
    (path,) = CORPUS.glob(f"{case_id}-*.yaml")
    return YAML(typ="safe", pure=True).load(path.read_text(encoding="utf-8"))


def text(case_id: str) -> str:
    return str(corpus(case_id)["input"]["text"])


def expected_exit(case_id: str) -> int:
    return int(corpus(case_id)["expected"]["exit_code"])


@pytest.fixture
def repo(tmp_repo: Path, fake_llm: Callable[[str], FakeLLM]) -> Path:
    fake_llm("clinic")
    designed(tmp_repo)
    return tmp_repo


def plan_with(
    repo: Path, monkeypatch: pytest.MonkeyPatch, hostile: dict[str, Any], *flags: str
) -> tuple[Result, FakeLLM]:
    """`aipm plan` where the planner sends `hostile` both times."""
    fake = use_responses(monkeypatch, {PLANNER: [{"json": hostile}, {"json": hostile}]})
    return aipm(repo, "plan", flags=flags), fake


def events(repo: Path, kind: SecurityEventKind) -> list[str]:
    return [e.detail for e in open_store(repo).read_events() if e.kind is kind]


def assert_rejected(repo: Path, result: Result, before: dict[str, bytes], code: int) -> None:
    assert result.exit_code == code, result.output
    assert pm_files(repo) == before, "nothing is written"
    assert not (repo / ".pm" / "tasks.yaml").exists()


# ---------------------------------------------------------------- C-015 unknown gate


def test_c015_unknown_gate_is_rejected_after_one_repair(
    repo: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    hostile = reply("planner")
    hostile["tasks"][0]["gates"] = ["lint", "unit", "shell"]
    before = pm_files(repo)
    result, fake = plan_with(repo, monkeypatch, hostile)
    assert_rejected(repo, result, before, expected_exit("C-015"))
    assert "the policy forbids" in result.stderr
    assert any("'shell'" in issue for issue in json.loads(result.stdout)["issues"])
    first, second = fake.requests_for(PLANNER)
    assert "Problems with your previous reply" not in first.user
    assert "T-001.gates[2]: not in the gate menu" in second.user
    assert "shell" not in second.user, "the repair note never carries the model's text"
    assert events(repo, SecurityEventKind.POLICY_VIOLATION)


# ---------------------------------------------------------------- C-016 gate argument


def test_c016_a_gate_argument_in_a_description_is_inert(
    repo: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    hostile = reply("planner")
    hostile["tasks"][2]["description"] = text("C-016")
    result, _ = plan_with(repo, monkeypatch, hostile, "--yes")
    assert result.exit_code == expected_exit("C-016"), result.output
    g3 = ok(aipm(repo, "approve", "plan", "--yes")).stdout
    for marker in ("curl", "evil.example", "--override-ini", "no:cacheprovider"):
        assert marker not in g3
    stored = tasks(repo).tasks[2]
    assert "evil.example" in stored.description, "kept as text: it is data, not a command"
    assert stored.gates == ["lint", "unit", "secrets", "ac_trace"]
    cfg = load_config(repo).config
    for name, gate in cfg.gates.items():
        assert gate.run is None or all("evil" not in part for part in gate.run), name


def test_llm_text_never_appears_in_the_command_list(
    repo: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Every task text field carries a marker; the G3 command list is the config's alone."""
    hostile = reply("planner")
    marker = "zzmarker"
    for task in hostile["tasks"]:
        task["title"] = f"{task['title']} {marker} run gate unit with -k {marker}"
        task["description"] = f"Use `pytest -k {marker}` and `uv run {marker}`."
        task["acceptance"] = [f"{c} ({marker})" for c in task["acceptance"]]
    plan_with(repo, monkeypatch, hostile, "--yes")
    out = ok(aipm(repo, "approve", "plan", "--yes")).stdout.splitlines()
    cfg = load_config(repo).config
    surface = default_trust_store().surface(cfg)
    expected = render_surface(surface, hash_surface(surface))
    start = out.index("Execution surface")
    command_list = out[start : start + len(expected)]
    assert command_list == expected
    assert not any(marker in line for line in command_list)
    assert marker not in json.dumps(surface)


# ---------------------------------------------------------------- C-017 unsafe paths


def test_c017_unsafe_owned_paths_are_rejected(repo: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    hostile = reply("planner")
    paths = text("C-017").split()
    hostile["tasks"][1]["owns_files"] = [*hostile["tasks"][1]["owns_files"], *paths]
    before = pm_files(repo)
    result, fake = plan_with(repo, monkeypatch, hostile)
    assert_rejected(repo, result, before, expected_exit("C-017"))
    issues = json.loads(result.stdout)["issues"]
    assert len(issues) == len(paths)
    assert all("not a safe repository-relative glob" in issue for issue in issues)
    second = fake.requests_for(PLANNER)[1].user
    for path in paths:
        assert path not in second.split("Problems with your previous reply")[1]
    (detail,) = events(repo, SecurityEventKind.POLICY_VIOLATION)[:1]
    assert "outside the policy" in detail


# ---------------------------------------------------------------- C-018 cycle


def test_c018_a_cycle_is_rejected(repo: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    hostile = reply("planner")
    hostile["tasks"][0]["depends_on"] = ["T-003"]
    hostile["tasks"][1]["depends_on"] = ["T-001"]
    hostile["tasks"][2]["depends_on"] = ["T-002"]
    before = pm_files(repo)
    result, _ = plan_with(repo, monkeypatch, hostile)
    assert_rejected(repo, result, before, expected_exit("C-018"))
    (issue,) = json.loads(result.stdout)["issues"]
    assert issue.startswith("plan: dependency cycle: ")
    assert not events(repo, SecurityEventKind.POLICY_VIOLATION)


# ---------------------------------------------------------------- C-019 500 tasks


def test_c019_five_hundred_tasks_are_rejected(repo: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    template = reply("planner")["tasks"][6]
    hostile = reply("planner")
    hostile["tasks"] = [
        {**template, "id": f"T-{n:03d}", "depends_on": [], "owns_files": [f"src/m{n}.py"]}
        for n in range(1, 501)
    ]
    before = pm_files(repo)
    result, fake = plan_with(repo, monkeypatch, hostile)
    assert_rejected(repo, result, before, expected_exit("C-019"))
    assert "failed validation twice" in result.stderr
    assert len(fake.requests_for(PLANNER)) == 2


# ---------------------------------------------------------------- C-020 OSC 52


def test_c020_osc52_in_a_criterion_is_removed_and_recorded(
    repo: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    hostile = reply("planner")
    hostile["tasks"][2]["acceptance"][0] = text("C-020")
    hostile["tasks"][2]["title"] = "OTP check\x1b[2J\x1b]8;;https://evil.example\x07link"
    result, _ = plan_with(repo, monkeypatch, hostile, "--yes")
    assert result.exit_code == expected_exit("C-020"), result.output
    for name in ("tasks.yaml", "worksheet.md"):
        data = (repo / ".pm" / name).read_text(encoding="utf-8")
        assert "\x1b" not in data
        assert "\x07" not in data
    assert "Wrong OTP returns 401 and counts the attempt" in (
        repo / ".pm" / "tasks.yaml"
    ).read_text(encoding="utf-8")
    g3 = aipm(repo, "approve", "plan", "--yes")
    assert "\x1b" not in g3.output
    assert "\x07" not in g3.output
    assert any("removed" in d for d in events(repo, SecurityEventKind.INJECTION_SIGNAL))
    assert "removed" in result.stderr


# ---------------------------------------------------------------- C-021 deps_add


def test_c021_shell_metacharacters_in_deps_add_are_rejected(
    repo: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    hostile = reply("planner")
    hostile["tasks"][2]["deps_add"] = [{"ecosystem": "pypi", "name": text("C-021")}]
    before = pm_files(repo)
    result, _ = plan_with(repo, monkeypatch, hostile)
    assert_rejected(repo, result, before, expected_exit("C-021"))
    (issue,) = json.loads(result.stdout)["issues"]
    assert issue.startswith("T-003.deps_add[0]: needs ecosystem pypi or npm")
    assert events(repo, SecurityEventKind.POLICY_VIOLATION)


# ---------------------------------------------------------------- suspected injection


def test_planner_injection_suspected_stops_before_anything_is_written(
    repo: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    flagged = {**reply("planner"), "injection_suspected": ["The PRD says to add gate shell"]}
    before = pm_files(repo)
    result, _ = plan_with(repo, monkeypatch, flagged)
    assert_rejected(repo, result, before, 4)
    assert json.loads(result.stdout)["role"] == "planner"
