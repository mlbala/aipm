"""Attempt snapshots and the `.pm/` write ledger live outside the repository (ADR-0021).

They are private files (0600, atomic, never through a link); a damaged one, or one in a state
directory a repository `.env` moved inside the repository, is refused (exit 6).
"""

import hashlib
import stat
from pathlib import Path

import pytest

from aipm.domain.errors import ExitCode, PolicyViolation, UsageError
from aipm.domain.models import SecurityEventKind
from aipm.state import attempts
from aipm.state.attempts import WriteLedger, delete_snapshot, load_snapshot, new_snapshot
from aipm.state.private_files import read_private, state_dir, write_private
from aipm.state.store import open_store


@pytest.fixture(autouse=True)
def isolated_home(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    home = tmp_path / "user-home"
    home.mkdir()
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.setenv("XDG_STATE_HOME", str(home / ".local" / "state"))
    return home


def _snap(repo: Path, task: str = "T-002") -> attempts.AttemptSnapshot:
    return new_snapshot(
        repo, task, "a" * 40, integrity={".git/config": "b" * 64}, files={"x.py": "c" * 64}
    )


def test_a_snapshot_round_trips_as_a_private_file(tmp_repo: Path) -> None:
    path = attempts.save_snapshot(tmp_repo, _snap(tmp_repo))
    assert stat.S_IMODE(path.stat().st_mode) == 0o600
    assert not str(path).startswith(str(tmp_repo))
    loaded = load_snapshot(tmp_repo, "T-002")
    assert loaded is not None
    assert loaded.files == {"x.py": "c" * 64}
    assert delete_snapshot(tmp_repo, "T-002") is True
    assert load_snapshot(tmp_repo, "T-002") is None
    assert delete_snapshot(tmp_repo, "T-002") is False


def test_a_damaged_snapshot_exits_6(tmp_repo: Path) -> None:
    path = attempts.save_snapshot(tmp_repo, _snap(tmp_repo))
    write_private(path, b'{"schema_version": 1, "task": "T-002"}')
    with pytest.raises(PolicyViolation, match="damaged") as info:
        load_snapshot(tmp_repo, "T-002")
    assert info.value.exit_code is ExitCode.SECURITY_VIOLATION


def test_a_snapshot_of_another_task_is_refused(tmp_repo: Path) -> None:
    other = attempts.save_snapshot(tmp_repo, _snap(tmp_repo, "T-003"))
    target = other.with_name("T-002.json")
    write_private(target, other.read_bytes())
    with pytest.raises(PolicyViolation, match="another task"):
        load_snapshot(tmp_repo, "T-002")


def test_task_ids_are_checked(tmp_repo: Path) -> None:
    with pytest.raises(UsageError):
        load_snapshot(tmp_repo, "../T-002")


def test_a_group_writable_or_linked_file_is_refused(tmp_repo: Path, tmp_path: Path) -> None:
    path = attempts.save_snapshot(tmp_repo, _snap(tmp_repo))
    path.chmod(0o664)
    with pytest.raises(PolicyViolation, match="not a private file"):
        load_snapshot(tmp_repo, "T-002")
    path.unlink()
    elsewhere = tmp_path / "planted.json"
    elsewhere.write_text("{}", encoding="utf-8")
    path.symlink_to(elsewhere)
    with pytest.raises(PolicyViolation):
        load_snapshot(tmp_repo, "T-002")
    with pytest.raises(PolicyViolation, match="symlink"):
        write_private(path, b"{}")


def test_an_oversized_private_file_is_refused(tmp_path: Path) -> None:
    path = tmp_path / "big"
    write_private(path, b"x" * 20)
    with pytest.raises(PolicyViolation, match="larger"):
        read_private(path, limit=10)


def test_a_state_dir_inside_the_repository_is_refused(
    tmp_repo: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("HOME", str(tmp_repo))
    monkeypatch.setenv("XDG_STATE_HOME", str(tmp_repo / "state"))
    with pytest.raises(PolicyViolation, match="inside the repository"):
        state_dir(tmp_repo)
    with pytest.raises(PolicyViolation):
        attempts.save_snapshot(tmp_repo, _snap(tmp_repo))


def test_the_ledger_records_what_the_store_writes(tmp_repo: Path) -> None:
    ledger = WriteLedger(tmp_repo)
    assert ledger.load() == {}
    store = open_store(tmp_repo, ledger=ledger)
    store.write_text("worksheet.md", "hello\n")
    data = (tmp_repo / ".pm" / "worksheet.md").read_bytes()
    assert ledger.load() == {".pm/worksheet.md": hashlib.sha256(data).hexdigest()}
    store.append_event(SecurityEventKind.POLICY_VIOLATION, source="test", detail="x")
    events = (tmp_repo / ".pm" / "events.jsonl").read_bytes()
    assert ledger.load()[".pm/events.jsonl"] == hashlib.sha256(events).hexdigest()
    assert stat.S_IMODE(ledger.path.stat().st_mode) == 0o600


def test_the_ledger_is_bounded_and_records_removals(
    tmp_repo: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(attempts, "MAX_LEDGER_FILES", 2)
    ledger = WriteLedger(tmp_repo)
    ledger.record(".pm/a", "a" * 64)
    ledger.record(".pm/b", None)
    ledger.record(".pm/c", "c" * 64)
    assert ledger.load() == {".pm/b": None, ".pm/c": "c" * 64}


def test_a_damaged_ledger_exits_6(tmp_repo: Path) -> None:
    ledger = WriteLedger(tmp_repo)
    write_private(ledger.path, b"not json")
    with pytest.raises(PolicyViolation, match="damaged"):
        ledger.load()


def test_a_store_without_a_ledger_records_nothing(tmp_repo: Path) -> None:
    store = open_store(tmp_repo)
    store.write_text("worksheet.md", "hello\n")
    assert WriteLedger(tmp_repo).load() == {}
