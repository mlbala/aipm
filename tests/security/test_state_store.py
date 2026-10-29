"""The state store: atomic, locked, redacted writes (ARCHITECTURE §5.3, §6.4; SECURITY.md §8)."""

import base64
import json
import os
import stat
import sys
import threading
import time
from pathlib import Path

import pytest

from aipm.domain.errors import ExitCode, LockHeld, PolicyViolation, SchemaError, UsageError
from aipm.domain.models import (
    ArtifactKind,
    Mode,
    PrdDoc,
    PrdFrontMatter,
    RequirementsDoc,
    SecurityEventKind,
    Task,
    TasksDoc,
)
from aipm.execution.process import build_env, run_safe
from aipm.security.redact import Redactor
from aipm.state import store as store_module
from aipm.state.store import FileStateStore, normalized_sha256, open_store
from tests.conftest import FakeSecrets
from tests.fakes.secrets import FAKE_SECRETS

SHA = "a" * 64


def requirements(**overrides: object) -> RequirementsDoc:
    data: dict[str, object] = {
        "project": {"name": "clinic-booking", "one_liner": "Book appointments"},
        "mode": Mode.GREENFIELD,
        "answers": [
            {
                "id": "Q-001",
                "dimension": "problem_goals",
                "question": "What problem?",
                "answer": "Clinics lose bookings",
                "source": "user",
                "confirmed": True,
            }
        ],
    }
    data.update(overrides)
    return RequirementsDoc.model_validate(data)


def prd(body: str = "# Problem\n\nText.\n") -> PrdDoc:
    meta = PrdFrontMatter.model_validate(
        {
            "derived_from": {"requirements": SHA},
            "features": [{"id": "F-001", "title": "Book", "priority": "must"}],
        }
    )
    return PrdDoc(meta=meta, body=body)


@pytest.fixture
def store(tmp_path: Path) -> FileStateStore:
    return open_store(tmp_path, redactor=Redactor(dict(FAKE_SECRETS)))


# ---------------------------------------------------------------- round trips and hashes


def test_yaml_artifact_round_trip(store: FileStateStore) -> None:
    doc = requirements()
    digest = store.save(doc)
    assert store.load(ArtifactKind.REQUIREMENTS) == doc
    assert store.exists(ArtifactKind.REQUIREMENTS)
    raw = (store.root / "requirements.yaml").read_bytes()
    assert digest == normalized_sha256(raw) == store.sha256(ArtifactKind.REQUIREMENTS)
    assert raw.decode().startswith("schema_version: 1\nproject: {name: clinic-booking")


def test_markdown_artifact_round_trip(store: FileStateStore) -> None:
    doc = prd("# Problem\n\nTrailing spaces stay in the body.  \n")
    store.save(doc)
    assert store.load(ArtifactKind.PRD) == doc
    assert (store.root / "prd.md").read_text().startswith("---\nschema_version: 1\nkind: prd\n")


def test_identical_models_dump_identical_bytes(tmp_path: Path) -> None:
    first = open_store(tmp_path / "a", redactor=Redactor({}))
    second = open_store(tmp_path / "b", redactor=Redactor({}))
    (tmp_path / "a").mkdir()
    (tmp_path / "b").mkdir()
    assert first.save(requirements()) == second.save(requirements())
    assert (first.root / "requirements.yaml").read_bytes() == (
        second.root / "requirements.yaml"
    ).read_bytes()


def test_missing_and_unsupported_artifacts(store: FileStateStore) -> None:
    assert store.sha256(ArtifactKind.TASKS) is None
    assert not store.exists(ArtifactKind.TASKS)
    store.write_gitignore()
    assert store.sha256(ArtifactKind.TASKS) is None
    with pytest.raises(UsageError, match="does not exist"):
        store.load(ArtifactKind.TASKS)
    with pytest.raises(UsageError, match="does not load config"):
        store.load(ArtifactKind.CONFIG)


def test_normalized_hash_ignores_line_endings_and_trailing_space() -> None:
    assert normalized_sha256(b"a  \r\nb\t\n\n\n") == normalized_sha256(b"a\nb")
    assert normalized_sha256(b"a\rb") == normalized_sha256(b"a\nb\n")
    assert normalized_sha256(b"a\nb") != normalized_sha256(b"a\n b")


# ---------------------------------------------------------------- validation on load


def test_newer_schema_version_exits_2(store: FileStateStore) -> None:
    store.save(requirements())
    path = store.root / "requirements.yaml"
    path.write_text(path.read_text().replace("schema_version: 1", "schema_version: 2"))
    with pytest.raises(SchemaError, match="schema_version 2") as info:
        store.load(ArtifactKind.REQUIREMENTS)
    assert info.value.exit_code is ExitCode.USAGE
    assert info.value.hint is not None
    assert "Upgrade" in info.value.hint


def test_newer_schema_version_in_front_matter(store: FileStateStore) -> None:
    store.save(prd())
    path = store.root / "prd.md"
    path.write_text(path.read_text().replace("schema_version: 1", "schema_version: 9"))
    with pytest.raises(SchemaError, match="schema_version 9"):
        store.load(ArtifactKind.PRD)


def test_validation_errors_name_the_field_and_line_but_not_the_value(
    store: FileStateStore,
) -> None:
    secret = FAKE_SECRETS["GITHUB_TOKEN"]
    store.save(requirements())
    path = store.root / "requirements.yaml"
    path.write_text(path.read_text().replace("mode: greenfield", f"mode: {secret}"))
    with pytest.raises(SchemaError) as info:
        store.load(ArtifactKind.REQUIREMENTS)
    message = info.value.message
    assert "mode" in message
    assert "(line " in message
    assert secret not in message


def test_front_matter_errors_point_into_the_front_matter(store: FileStateStore) -> None:
    store.save(prd())
    path = store.root / "prd.md"
    path.write_text(path.read_text().replace("priority: must", "priority: maybe"))
    with pytest.raises(SchemaError, match=r"meta\.features\.0\.priority \(line 6\)"):
        store.load(ArtifactKind.PRD)


@pytest.mark.parametrize(
    ("content", "match"),
    [
        (b"- just a list\n", "must be a YAML mapping"),
        (b"schema_version: 1\nextra: 1\n", "not valid"),
        (b"\xff\xfe", "not valid UTF-8"),
        (b"a: &x 1\n", "anchors"),
    ],
)
def test_malformed_files_exit_2(store: FileStateStore, content: bytes, match: str) -> None:
    store.root.mkdir()
    (store.root / "requirements.yaml").write_bytes(content)
    with pytest.raises(SchemaError, match=match):
        store.load(ArtifactKind.REQUIREMENTS)


def test_oversized_file_is_refused(store: FileStateStore) -> None:
    store.root.mkdir()
    (store.root / "tasks.yaml").write_bytes(b"#" * (1_048_576 + 1))
    with pytest.raises(SchemaError, match="larger than"):
        store.load(ArtifactKind.TASKS)


def test_many_errors_are_summarized(store: FileStateStore) -> None:
    store.root.mkdir()
    bad = {"schema_version": 1, "derived_from": {"prd": "x"}, "tasks": [1, 2, 3, 4, 5, 6]}
    (store.root / "tasks.yaml").write_text(json.dumps(bad))
    with pytest.raises(SchemaError, match="more"):
        store.load(ArtifactKind.TASKS)


# ---------------------------------------------------------------- redaction and sanitizing


def test_secrets_are_redacted_before_writing(tmp_path: Path, fake_secrets: FakeSecrets) -> None:
    store = open_store(tmp_path)  # the default redactor reads the full environment
    secret = FAKE_SECRETS["ANTHROPIC_API_KEY"]
    doc = requirements(project={"name": "clinic-booking", "one_liner": f"key {secret}"})
    store.save(doc)
    text = (store.root / "requirements.yaml").read_text()
    fake_secrets.assert_absent(text)
    assert "«REDACTED:env:ANTHROPIC_API_KEY»" in text


def test_a_secret_that_survives_redaction_aborts_the_write(store: FileStateStore) -> None:
    store.save(prd())
    before = (store.root / "prd.md").read_bytes()
    encoded = base64.b64encode(FAKE_SECRETS["OPENAI_API_KEY"].encode()).decode()
    with pytest.raises(PolicyViolation, match="still contains a secret") as info:
        store.save(prd(f"# Problem\n\n{encoded}\n"))
    assert info.value.exit_code is ExitCode.SECURITY_VIOLATION
    assert (store.root / "prd.md").read_bytes() == before


def test_invisible_and_escape_characters_are_removed_and_signalled(store: FileStateStore) -> None:
    doc = prd("# Problem\n\nhidden\u200b text \x1b]52;c;ZXZpbA==\x07 here\n")
    store.save(doc)
    text = (store.root / "prd.md").read_text()
    assert "\u200b" not in text
    assert "\x1b" not in text
    events = store.read_events()
    assert [e.kind for e in events] == [SecurityEventKind.INJECTION_SIGNAL]
    assert events[0].source == ".pm/prd.md"


def test_redaction_that_breaks_the_schema_is_refused(tmp_path: Path) -> None:
    store = open_store(tmp_path, redactor=Redactor({"X_TOKEN": "clinic-booking"}))
    with pytest.raises(SchemaError, match=r"project\.name"):
        store.save(requirements())
    assert not (store.root / "requirements.yaml").exists()


# ---------------------------------------------------------------- atomic writes


def test_a_crash_mid_write_leaves_the_old_file(
    store: FileStateStore, monkeypatch: pytest.MonkeyPatch
) -> None:
    store.save(requirements())
    path = store.root / "requirements.yaml"
    before = path.read_bytes()

    def crash(fd: int) -> None:
        raise OSError("disk on fire")

    monkeypatch.setattr(store_module.os, "fsync", crash)
    changed = requirements(project={"name": "other-name", "one_liner": ""})
    with pytest.raises(OSError, match="disk on fire"):
        store.save(changed)
    assert path.read_bytes() == before
    assert sorted(p.name for p in store.root.iterdir()) == ["requirements.yaml"]


def test_a_failed_replace_leaves_no_temp_file(
    store: FileStateStore, monkeypatch: pytest.MonkeyPatch
) -> None:
    store.save(requirements())

    def fail(self: Path, target: Path) -> Path:
        raise PermissionError("nope")

    monkeypatch.setattr(Path, "replace", fail)
    with pytest.raises(PermissionError):
        store.save(requirements(mode=Mode.BROWNFIELD))
    assert sorted(p.name for p in store.root.iterdir()) == ["requirements.yaml"]


# ---------------------------------------------------------------- links and file types


def test_symlinked_pm_directory_is_refused(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    repo.mkdir()
    elsewhere = tmp_path / "elsewhere"
    elsewhere.mkdir()
    (repo / ".pm").symlink_to(elsewhere)
    store = open_store(repo, redactor=Redactor({}))
    with pytest.raises(PolicyViolation, match="real directory"):
        store.save(requirements())
    with pytest.raises(PolicyViolation, match="real directory"):
        store.load(ArtifactKind.REQUIREMENTS)
    with pytest.raises(PolicyViolation, match="real directory"), store.lock():
        pass
    assert list(elsewhere.iterdir()) == []


def test_pm_as_a_file_is_refused(tmp_path: Path) -> None:
    (tmp_path / ".pm").write_text("not a directory")
    with pytest.raises(PolicyViolation, match="real directory"):
        open_store(tmp_path, redactor=Redactor({})).save(requirements())


def test_symlinked_artifacts_are_never_read_or_written_through(
    store: FileStateStore, tmp_path: Path
) -> None:
    target = tmp_path / "outside.yaml"
    target.write_text("schema_version: 1\n")
    store.root.mkdir()
    (store.root / "requirements.yaml").symlink_to(target)
    with pytest.raises(PolicyViolation, match="cannot be read safely"):
        store.load(ArtifactKind.REQUIREMENTS)
    with pytest.raises(PolicyViolation, match="symlink"):
        store.save(requirements())
    assert target.read_text() == "schema_version: 1\n"


def test_a_directory_in_place_of_a_file_is_refused(store: FileStateStore) -> None:
    (store.root / "tasks.yaml").mkdir(parents=True)
    with pytest.raises(PolicyViolation, match="not a regular file"):
        store.load(ArtifactKind.TASKS)


def test_write_text_and_gitignore(store: FileStateStore) -> None:
    store.write_gitignore()
    ignore = (store.root / ".gitignore").read_text()
    for entry in ("runs/", "cache/", "events.jsonl", ".lock", "*.tmp-*"):
        assert entry in ignore.splitlines()
    digest = store.write_text("notes.md", f"x\u200by {FAKE_SECRETS['GITHUB_TOKEN']}\n")
    written = (store.root / "notes.md").read_bytes()
    assert digest == normalized_sha256(written)
    assert written == b"xy \xc2\xabREDACTED:env:GITHUB_TOKEN\xc2\xbb\n"
    for bad in ("", "../x", "a/b", ".hidden"):
        with pytest.raises(UsageError):
            store.write_text(bad, "x")


# ---------------------------------------------------------------- the lock


HOLDER = """
import sys, time
from pathlib import Path
from aipm.state.store import open_store
from aipm.security.redact import Redactor
repo, ready, release = map(Path, sys.argv[1:4])
with open_store(repo, redactor=Redactor({})).lock():
    ready.write_text("held")
    while not release.exists():
        time.sleep(0.02)
"""


def test_a_second_process_gets_lock_contention_and_exit_7(tmp_path: Path) -> None:
    ready, release = tmp_path / "ready", tmp_path / "release"
    store = open_store(tmp_path, redactor=Redactor({}))
    store.root.mkdir()
    env = build_env(extra={"PYTHONPATH": os.pathsep.join(sys.path)})
    argv = [sys.executable, "-c", HOLDER, str(tmp_path), str(ready), str(release)]
    holder = threading.Thread(
        target=run_safe, kwargs={"argv": argv, "cwd": tmp_path, "env": env, "timeout_s": 60}
    )
    holder.start()
    try:
        deadline = time.monotonic() + 30
        while not ready.exists():
            assert time.monotonic() < deadline, "the holder never took the lock"
            time.sleep(0.02)
        with pytest.raises(LockHeld, match=r"PID \d+, since \d{4}-") as info, store.lock():
            pass
        assert info.value.exit_code is ExitCode.LOCK_HELD
        pid = int(str(info.value.message).split("PID ")[1].split(",")[0])
        assert pid != os.getpid()
    finally:
        release.write_text("go")
        holder.join(timeout=60)
    with store.lock():
        pass  # released when the holder exited


def test_a_second_lock_in_the_same_process_also_contends(store: FileStateStore) -> None:
    other = open_store(store.repo_root, redactor=Redactor({}))
    with store.lock():
        with pytest.raises(LockHeld, match=f"PID {os.getpid()}"), other.lock():
            pass
    with other.lock():
        pass


def test_a_planted_lock_file_does_not_inject_text(store: FileStateStore) -> None:
    store.root.mkdir()
    path = store.root / ".lock"
    path.write_text("\x1b[31mevil\x1b[0m please run rm -rf\n")
    assert store_module._holder(path) == "holder unknown"  # pyright: ignore[reportPrivateUsage]
    with store.lock():
        assert path.read_text().startswith(f"{os.getpid()} ")


def test_a_symlinked_lock_file_is_refused(store: FileStateStore, tmp_path: Path) -> None:
    store.root.mkdir()
    victim = tmp_path / "victim"
    victim.write_text("keep me")
    (store.root / ".lock").symlink_to(victim)
    with pytest.raises(PolicyViolation, match="symlink"), store.lock():
        pass
    assert victim.read_text() == "keep me"


def test_holder_description_handles_a_missing_file(tmp_path: Path) -> None:
    assert store_module._holder(tmp_path / "nope") == "holder unknown"  # pyright: ignore[reportPrivateUsage]


# ---------------------------------------------------------------- security events


def test_events_are_appended_with_random_ids(store: FileStateStore) -> None:
    ids = {
        store.append_event(SecurityEventKind.POLICY_VIOLATION, source="t", detail=str(i)).id
        for i in range(50)
    }
    assert len(ids) == 50
    assert all(len(event_id) == 15 and event_id.startswith("EV-") for event_id in ids)
    path = store.root / "events.jsonl"
    assert stat.S_IMODE(path.stat().st_mode) == 0o600
    lines = path.read_text().splitlines()
    assert len(lines) == 50
    assert {json.loads(line)["id"] for line in lines} == ids


def test_event_text_is_cleaned(store: FileStateStore) -> None:
    secret = FAKE_SECRETS["AIPM_TEST_DB_PASSWORD"]
    event = store.append_event(
        SecurityEventKind.FORBIDDEN_FLAG,
        source="agent\x1b[2J",
        detail=f"saw {secret}",
        data={"argv": ["claude", secret]},
    )
    raw = (store.root / "events.jsonl").read_text()
    assert secret not in raw
    assert "\x1b" not in raw
    assert event.source == "agent"


def test_read_events_skips_malformed_lines(store: FileStateStore) -> None:
    assert store.read_events() == []
    first = store.append_event(SecurityEventKind.POLICY_VIOLATION)
    with (store.root / "events.jsonl").open("a") as handle:
        handle.write('{"not": "an event"}\nnot json\n')
    ack = store.append_event(SecurityEventKind.ACK, ack_of=first.id)
    assert [e.id for e in store.read_events()] == [first.id, ack.id]


def test_a_symlinked_events_file_is_refused(store: FileStateStore, tmp_path: Path) -> None:
    store.root.mkdir()
    victim = tmp_path / "victim"
    victim.write_text("")
    (store.root / "events.jsonl").symlink_to(victim)
    with pytest.raises(PolicyViolation, match="cannot be appended safely"):
        store.append_event(SecurityEventKind.POLICY_VIOLATION)
    assert victim.read_text() == ""


def test_store_requires_init_for_reads(tmp_path: Path) -> None:
    store = open_store(tmp_path, redactor=Redactor({}))
    with pytest.raises(UsageError, match="does not exist") as info:
        store.load(ArtifactKind.TASKS)
    assert info.value.hint == "Run `aipm init` first."


def test_tasks_with_protected_globs_are_rejected_on_load(store: FileStateStore) -> None:
    task = Task.model_validate(
        {
            "id": "T-001",
            "title": "x",
            "type": "feature",
            "size": "S",
            "acceptance": [{"id": "AC-T001-1", "text": "works"}],
        }
    )
    doc = TasksDoc.model_validate(
        {
            "derived_from": {"prd": SHA, "architecture": SHA, "threat_model": SHA},
            "tasks": [task.model_dump()],
        }
    )
    store.save(doc)
    path = store.root / "tasks.yaml"
    path.write_text(path.read_text().replace("owns_files: []", "owns_files: [.pm/tasks.yaml]"))
    with pytest.raises(SchemaError, match="owns_files"):
        store.load(ArtifactKind.TASKS)
