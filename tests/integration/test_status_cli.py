"""`aipm status` and bare `aipm` (build prompt 04): read-only, no LLM, `--ack` recorded."""

import json
from collections.abc import Callable
from datetime import UTC, datetime
from pathlib import Path

import pytest

from aipm.cli.main import app
from aipm.domain.models import (
    Blocked,
    BlockedReason,
    Done,
    SecurityEventKind,
    TaskStatus,
)
from aipm.llm.errors import ProviderError
from aipm.llm.fake import FakeLLM
from aipm.state.store import open_store
from tests.integration.flow import aipm, designed, discovered, ok, runner, tasks

type UseFake = Callable[[str], FakeLLM]


@pytest.fixture
def planned(tmp_repo: Path, fake_llm: UseFake, monkeypatch: pytest.MonkeyPatch) -> Path:
    """A planned repository; afterwards any LLM call fails, so status must not make one."""
    fake_llm("clinic")
    designed(tmp_repo)
    ok(aipm(tmp_repo, "plan", flags=["--yes"]))

    def no_llm(llm: object, **_: object) -> FakeLLM:
        raise ProviderError("status must not call an LLM")

    monkeypatch.setattr("aipm.llm.gateway.make_provider", no_llm)
    return tmp_repo


def set_status(repo: Path, task_id: str, status: TaskStatus, **extra: object) -> None:
    doc = tasks(repo)
    index = next(i for i, t in enumerate(doc.tasks) if t.id == task_id)
    doc.tasks[index] = doc.tasks[index].model_copy(update={"status": status, **extra})
    open_store(repo).save(doc)


# ---------------------------------------------------------------- the view


def test_status_outside_a_repository(tmp_path: Path) -> None:
    result = runner.invoke(app, ["-C", str(tmp_path), "status"])
    assert result.exit_code == 2
    assert "is not inside a git repository" in result.stderr


def test_status_before_any_plan(tmp_repo: Path) -> None:
    ok(runner.invoke(app, ["-C", str(tmp_repo), "init"]))
    result = ok(aipm(tmp_repo, "status"))
    assert "Phase: initialized" in result.stdout
    assert "Tasks: 0 (todo 0, in progress 0, blocked 0, done 0, skipped 0)" in result.stdout


def test_status_after_planning(planned: Path) -> None:
    out = ok(aipm(planned, "status")).stdout
    assert "Phase: plan_draft" in out
    assert "Next: aipm trust" in out
    assert "Tasks: 7 (todo 7, in progress 0, blocked 0, done 0, skipped 0)" in out
    assert "[------------------------------]   0% (0/7)" in out
    assert "features: F-001 (must): Book an appointment with a one-time code;" in out
    assert "TM-01 (high): One-time code brute force" in out
    assert "TM-04" not in out, "low threats are not listed"
    assert "Spend: not recorded yet" in out
    assert "budget $10.00 per run, $2.00 per task" in out
    assert "All tasks:" not in out


def test_all_and_task(planned: Path) -> None:
    out = ok(aipm(planned, "status", "--all")).stdout
    assert "  T-003 [todo] M One-time code verification with a rate limit (after T-002)" in out
    out = ok(aipm(planned, "status", "--task", "T-003")).stdout
    assert out.startswith("T-003: One-time code verification with a rate limit\n")
    assert "  traces: F-001, TM-01" in out
    assert "  new dependencies: pypi:slowapi" in out
    assert "    AC-T003-2: The sixth attempt within ten minutes returns 429" in out


@pytest.mark.parametrize(("value", "message"), [
    ("T-099", "there is no task T-099"), ("T-1", "--task takes a task ID"),
])  # fmt: skip
def test_bad_task_option(planned: Path, value: str, message: str) -> None:
    result = aipm(planned, "status", "--task", value)
    assert result.exit_code == 2
    assert message in result.stderr


def test_blocked_and_done_tasks(planned: Path) -> None:
    set_status(planned, "T-001", TaskStatus.DONE,
               done=Done(commit="a" * 40, at=datetime(2026, 10, 29, tzinfo=UTC)))  # fmt: skip
    set_status(planned, "T-002", TaskStatus.BLOCKED, blocked=Blocked(
        reason=BlockedReason.AGENT_BLOCKED, detail="Unclear slot length",
        question="How long is one slot?"))  # fmt: skip
    out = ok(aipm(planned, "status")).stdout
    assert "Tasks: 7 (todo 5, in progress 0, blocked 1, done 1, skipped 0)" in out
    assert "[####--------------------------]  14% (1/7)" in out
    assert "  T-002 Slots and appointments without double booking: agent_blocked" in out
    assert "    agent says: How long is one slot?" in out


def test_json(planned: Path) -> None:
    env = json.loads(ok(aipm(planned, "status", flags=["--json"])).stdout)
    data = env["data"]
    assert data["counts"]["todo"] == 7
    assert data["phase"]["next_command"] == "aipm trust"
    assert data["uncovered"]["threats"][0].startswith("TM-01")
    assert data["spend"] == {"usd": None, "tokens": None, "budget_run_usd": 10.0,
                             "budget_task_usd": 2.0, "budget_run_tokens": 2000000}  # fmt: skip


def test_hostile_task_text_is_printed_inert(planned: Path) -> None:
    doc = tasks(planned)
    doc.tasks[0] = doc.tasks[0].model_copy(update={"title": "Safe title"})
    open_store(planned).save(doc)
    path = planned / ".pm" / "tasks.yaml"
    text = path.read_text(encoding="utf-8").replace(
        "title: Safe title", 'title: "Evil\\e]52;c;eA==\\a [bold]x[/bold]"'
    )
    path.write_text(text, encoding="utf-8")
    out = ok(aipm(planned, "status", "--all")).stdout
    assert "\x1b" not in out
    assert "\x07" not in out
    assert "[bold]x[/bold]" in out, "printed as text, never as markup"


# ---------------------------------------------------------------- security events and --ack


def test_events_are_listed_and_acknowledged(planned: Path) -> None:
    store = open_store(planned)
    event = store.append_event(SecurityEventKind.POLICY_VIOLATION, source="test",
                               detail="something happened")  # fmt: skip
    out = ok(aipm(planned, "status")).stdout
    assert "Security events (1 unacknowledged):" in out
    assert f"  {event.id} " in out
    assert "something happened" in out
    result = ok(aipm(planned, "status", "--ack", event.id))
    assert f"Acknowledged {event.id}." in result.stdout
    ack = store.read_events()[-1]
    assert (ack.kind, ack.ack_of) == (SecurityEventKind.ACK, event.id)
    assert "Security events: none unacknowledged" in ok(aipm(planned, "status")).stdout
    again = aipm(planned, "status", "--ack", event.id)
    assert again.exit_code == 2
    assert "already acknowledged" in again.stderr
    of_ack = aipm(planned, "status", "--ack", ack.id)
    assert of_ack.exit_code == 2
    assert "not a security event recorded on this machine" in of_ack.stderr


@pytest.mark.parametrize("value", ["EV-000000000000", "EV-zz", "../x"])
def test_ack_only_takes_recorded_ids(planned: Path, value: str) -> None:
    result = aipm(planned, "status", "--ack", value)
    assert result.exit_code == 2


def test_ack_json(planned: Path) -> None:
    event = open_store(planned).append_event(SecurityEventKind.INJECTION_SIGNAL, source="t")
    env = json.loads(ok(aipm(planned, "status", "--ack", event.id, flags=["--json"])).stdout)
    assert env["data"] == {"acked": event.id}


# ---------------------------------------------------------------- bare aipm


def test_bare_aipm_before_init(tmp_repo: Path) -> None:
    out = ok(runner.invoke(app, ["--non-interactive", "-C", str(tmp_repo)])).stdout
    assert out == "Phase: uninitialized\nNext: aipm init\n"


def test_bare_aipm_reports_the_phase_and_next_step(tmp_repo: Path, fake_llm: UseFake) -> None:
    fake_llm("clinic")
    discovered(tmp_repo)
    out = ok(aipm(tmp_repo)).stdout
    assert out == "Phase: prd_approved\nNext: aipm design\n"
    env = json.loads(ok(aipm(tmp_repo, flags=["--json"])).stdout)
    assert env["command"] == "aipm"
    assert env["data"]["phase"] == "prd_approved"


def test_bare_aipm_reports_staleness(tmp_repo: Path, fake_llm: UseFake) -> None:
    fake_llm("clinic")
    designed(tmp_repo)
    path = tmp_repo / ".pm" / "requirements.yaml"
    path.write_text(path.read_text(encoding="utf-8") + "# edited\n", encoding="utf-8")
    out = ok(aipm(tmp_repo)).stdout
    assert "Phase: prd_draft" in out
    assert (
        "stale: requirements.yaml changed after the PRD was written → the PRD, the "
        "architecture and the threat model are stale"
    ) in out
    assert "Next: aipm discover" in out


def test_bare_aipm_offers_the_next_command(
    tmp_repo: Path, fake_llm: UseFake, monkeypatch: pytest.MonkeyPatch
) -> None:
    fake_llm("clinic")
    discovered(tmp_repo)
    monkeypatch.setattr("aipm.cli.output.stdin_is_terminal", lambda: True)
    declined = ok(aipm(tmp_repo, input="n\n"))
    assert "Run `aipm design` now?" in declined.stdout
    assert not (tmp_repo / ".pm" / "architecture.md").exists()
    accepted = ok(aipm(tmp_repo, input="y\nn\n"))
    assert "G2 (design approval): pending" in accepted.stdout
    assert (tmp_repo / ".pm" / "architecture.md").exists()
