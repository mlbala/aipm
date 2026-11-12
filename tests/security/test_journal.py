"""The run journal (ARCHITECTURE §6.3, §12.6): append-only, fsync'd, and trusted for resume only
when the write ledger outside the repository says aipm wrote it."""

import json
import os
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from aipm.app import runtime
from aipm.domain.errors import PolicyViolation, UsageError
from aipm.domain.models import JournalEvent, JournalEventType
from aipm.execution import journal
from aipm.execution.journal import Journal, find_resumable, load, replay
from aipm.state.store import FileStateStore
from tests.fakes.secrets import FAKE_SECRETS
from tests.integration.conftest import UserDirs, user_dirs  # noqa: F401 - an autouse fixture

RUN = "r-20261112-1200-ab12"
OTHER = "r-20261112-1200-cd34"
SHA = "a" * 40


@pytest.fixture
def store(tmp_path: Path, user_dirs: UserDirs) -> FileStateStore:  # noqa: F811
    repo = tmp_path / "repo"
    repo.mkdir()
    return runtime.open_repo_store(repo)


def journal_path(store: FileStateStore, run_id: str = RUN) -> Path:
    return store.root / "runs" / run_id / "journal.jsonl"


def started(store: FileStateStore, run_id: str = RUN, kind: str = "build") -> Journal:
    j = Journal(store, run_id)
    j.append(
        JournalEventType.RUN_STARTED,
        data={"kind": kind, "integration": "aipm/integration", "base": SHA},
    )
    return j


def test_each_event_is_one_fsynced_line(
    store: FileStateStore, monkeypatch: pytest.MonkeyPatch
) -> None:
    synced: list[int] = []
    real = os.fsync
    monkeypatch.setattr(os, "fsync", lambda fd: (synced.append(fd), real(fd))[1])
    j = started(store)
    j.append(JournalEventType.TASK_SCHEDULED, task="T-001", attempt=1)
    lines = journal_path(store).read_text(encoding="utf-8").splitlines()
    assert [json.loads(line)["seq"] for line in lines] == [0, 1]
    assert len(synced) >= 2  # the file each time, the directory when it was created
    assert [e.type for e in load(store, RUN) or []] == [
        JournalEventType.RUN_STARTED,
        JournalEventType.TASK_SCHEDULED,
    ]


def test_journal_lines_are_redacted(store: FileStateStore, monkeypatch: pytest.MonkeyPatch) -> None:
    for name, value in FAKE_SECRETS.items():
        monkeypatch.setenv(name, value)
    store = runtime.open_repo_store(store.repo_root)
    j = started(store)
    j.append(
        JournalEventType.TASK_BLOCKED,
        task="T-001",
        data={"detail": f"key {FAKE_SECRETS['GITHUB_TOKEN']}"},
    )
    text = journal_path(store).read_text(encoding="utf-8")
    for value in FAKE_SECRETS.values():
        assert value not in text


def test_appending_through_a_link_or_more_than_one_line_is_refused(
    store: FileStateStore, tmp_path: Path
) -> None:
    started(store)
    with pytest.raises(UsageError, match="one line"):
        store.append_run_line(RUN, ["journal.jsonl"], "a\nb")
    target = tmp_path / "elsewhere"
    target.write_text("", encoding="utf-8")
    link_dir = store.root / "runs" / OTHER
    link_dir.mkdir(parents=True)
    (link_dir / "journal.jsonl").symlink_to(target)
    with pytest.raises(PolicyViolation, match="appended safely"):
        store.append_run_line(OTHER, ["journal.jsonl"], "{}")
    assert target.read_text(encoding="utf-8") == ""
    with pytest.raises(UsageError):
        store.append_run_line("../escape", ["journal.jsonl"], "{}")


def test_a_planted_journal_is_never_loaded(store: FileStateStore) -> None:
    path = journal_path(store, OTHER)
    path.parent.mkdir(parents=True)
    event = JournalEvent(seq=0, ts=datetime.now(UTC), run=OTHER, type=JournalEventType.RUN_STARTED,
                         data={"kind": "build"})  # fmt: skip
    path.write_text(event.model_dump_json() + "\n", encoding="utf-8")
    assert load(store, OTHER) is None
    assert find_resumable(store) is None


def test_a_journal_changed_after_aipm_wrote_it_is_not_trusted(store: FileStateStore) -> None:
    j = started(store)
    j.append(JournalEventType.TASK_SCHEDULED, task="T-001", attempt=1)
    path = journal_path(store)
    lines = path.read_text(encoding="utf-8").splitlines()
    forged = json.loads(lines[1])
    forged["type"] = "task_committed"
    path.write_text(lines[0] + "\n" + json.dumps(forged) + "\n", encoding="utf-8")
    assert load(store, RUN) is None


def test_a_line_appended_but_not_yet_recorded_is_dropped(store: FileStateStore) -> None:
    """aipm stopped between appending a line and recording the file's new hash."""
    j = started(store)
    j.append(JournalEventType.TASK_SCHEDULED, task="T-001", attempt=1)
    unrecorded = JournalEvent(
        seq=2,
        ts=datetime.now(UTC),
        run=RUN,
        type=JournalEventType.TASK_COMMITTED,
        task="T-001",
        attempt=1,
        data={"commit": SHA},
    )
    with journal_path(store).open("a", encoding="utf-8") as handle:
        handle.write(unrecorded.model_dump_json() + "\n" + '{"v":1,"seq":3')  # and a cut line
    events = load(store, RUN)
    assert events is not None
    assert [e.seq for e in events] == [0, 1]
    # Two unrecorded lines are one too many.
    with journal_path(store).open("a", encoding="utf-8") as handle:
        handle.write("}\n")
    assert load(store, RUN) is None


def test_lines_for_another_run_or_not_events_are_skipped(store: FileStateStore) -> None:
    j = started(store)
    store.append_run_line(RUN, ["journal.jsonl"], '{"not": "an event"}')
    other = JournalEvent(seq=9, ts=datetime.now(UTC), run=OTHER, type=JournalEventType.RUN_FINISHED)
    store.append_run_line(RUN, ["journal.jsonl"], other.model_dump_json())
    j.append(JournalEventType.TASK_SCHEDULED, task="T-001", attempt=1)
    assert [e.seq for e in load(store, RUN) or []] == [0, 1]


def test_the_newest_unfinished_build_run_is_resumed(store: FileStateStore) -> None:
    assert find_resumable(store) is None
    old = started(store, OTHER)
    assert find_resumable(store) == OTHER
    new = started(store, RUN)
    assert find_resumable(store) == RUN
    new.append(JournalEventType.RUN_FINISHED)
    assert find_resumable(store) is None  # the older unfinished run is never picked up
    old.append(JournalEventType.RUN_FINISHED)
    assert find_resumable(store) is None


def test_runs_are_ordered_by_start_time_not_by_id(
    store: FileStateStore, monkeypatch: pytest.MonkeyPatch
) -> None:
    later = datetime.now(UTC) + timedelta(minutes=1)
    started(store, RUN)  # "r-…-ab12" sorts first
    real_now = datetime.now

    class Later(datetime):
        @classmethod
        def now(cls, tz: object = None) -> "Later":  # type: ignore[override]
            del tz
            return Later.fromtimestamp(later.timestamp(), UTC)

    monkeypatch.setattr(journal, "datetime", Later)
    started(store, "r-20261112-1200-0000")
    monkeypatch.setattr(journal, "datetime", datetime)
    assert real_now(UTC) < later
    assert find_resumable(store) == "r-20261112-1200-0000"


def test_verify_journals_and_other_kinds_are_not_build_runs(store: FileStateStore) -> None:
    store.save_run_text(OTHER, ["journal.jsonl"], json.dumps({"v": 1}) + "\n")
    started(store, RUN, kind="verify")
    assert find_resumable(store) is None


def test_replay_sums_spend_attempts_commits_and_merges() -> None:
    now = datetime.now(UTC)

    def event(
        seq: int,
        type_: JournalEventType,
        task: str | None = None,
        attempt: int | None = None,
        **data: object,
    ) -> JournalEvent:
        return JournalEvent.model_validate(
            {"seq": seq, "ts": now, "run": RUN, "type": type_, "task": task, "attempt": attempt,
             "data": data}
        )  # fmt: skip

    events = [
        event(
            0, JournalEventType.RUN_STARTED, kind="build", integration="aipm/integration", base=SHA
        ),
        event(1, JournalEventType.AGENT_FINISHED, "T-001", 1, cost_usd=0.25),
        event(2, JournalEventType.AGENT_FINISHED, "T-001", 2, cost_usd=0.5),
        event(3, JournalEventType.TASK_COMMITTED, "T-001", 2, commit="b" * 40),
        event(4, JournalEventType.TASK_MERGED, "T-001", 2, commit="c" * 40),
        event(5, JournalEventType.AGENT_FINISHED, "T-002", 1, cost_usd="lots"),
        event(6, JournalEventType.TASK_COMMITTED, "T-002", 1, commit="not a sha"),
        event(7, JournalEventType.AGENT_FINISHED, "T-003", 1, cost_usd=-5),
        event(8, JournalEventType.TASK_BLOCKED, "T-003", 1),
        event(11, JournalEventType.AGENT_FINISHED, None, None, cost_usd=1e9),
    ]
    state = replay(RUN, events)
    assert (state.kind, state.integration, state.base) == ("build", "aipm/integration", SHA)
    assert state.spent_usd == pytest.approx(0.75)
    assert state.next_seq == 12
    one, two, three = state.tasks["T-001"], state.tasks["T-002"], state.tasks["T-003"]
    assert (one.attempts, one.committed, one.committed_attempt, one.merged) == (
        2,
        "b" * 40,
        2,
        "c" * 40,
    )
    assert (two.committed, two.merged, two.blocked) == (None, None, False)
    assert three.blocked


def test_an_agent_that_never_finished_is_charged_its_task_budget() -> None:
    now = datetime.now(UTC)
    events = [
        JournalEvent(seq=0, ts=now, run=RUN, type=JournalEventType.RUN_STARTED,
                     data={"kind": "build", "task_usd": 2.0}),
        JournalEvent(seq=1, ts=now, run=RUN, type=JournalEventType.AGENT_STARTED, task="T-001",
                     attempt=1),
        JournalEvent(seq=2, ts=now, run=RUN, type=JournalEventType.AGENT_FINISHED, task="T-001",
                     attempt=1, data={"cost_usd": 0.4}),
        JournalEvent(seq=3, ts=now, run=RUN, type=JournalEventType.AGENT_STARTED, task="T-002",
                     attempt=1),
    ]  # fmt: skip
    state = replay(RUN, events)
    assert state.spent_usd == pytest.approx(2.4)  # 0.4 reported, 2.0 for the one killed
    assert state.tasks["T-002"].dispatches == 1
