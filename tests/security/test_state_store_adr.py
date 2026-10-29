"""The ADR directory and hashed loads in the state store (build prompt 04, SECURITY.md §4).

`.pm/adr/` must be a real directory, files are read without following links, only names aipm
would write are read, and regenerating replaces the whole set.
"""

import hashlib
from datetime import UTC, datetime
from pathlib import Path

import pytest

from aipm.domain.errors import PolicyViolation, UsageError
from aipm.domain.models import (
    AdrDoc,
    AdrFrontMatter,
    ApprovalGate,
    ApprovalsDoc,
    ArtifactKind,
    OverrideReason,
    StaleOverride,
)
from aipm.domain.models.artifacts import adr_file_name, is_adr_file_name
from aipm.state.store import FileStateStore
from tests.conftest import FakeSecrets

EMPTY = hashlib.sha256(b"").hexdigest()


def adr(n: int, title: str, body: str = "We decided.\n") -> AdrDoc:
    return AdrDoc(meta=AdrFrontMatter(id=f"ADR-{n:04d}", title=title), body=body)


@pytest.fixture
def store(tmp_path: Path) -> FileStateStore:
    (tmp_path / ".pm").mkdir()
    return FileStateStore(tmp_path)


def test_adr_file_names_are_built_by_aipm() -> None:
    assert adr_file_name("ADR-0001", "Use FastAPI + Postgres!") == "0001-use-fastapi-postgres.md"
    assert adr_file_name("ADR-0002", "../../etc/passwd") == "0002-etc-passwd.md"
    assert adr_file_name("ADR-0003", "日本語") == "0003-decision.md"
    assert len(adr_file_name("ADR-0004", "x" * 300)) <= 64
    assert is_adr_file_name("0001-a.md")
    for bad in ("1-a.md", "0001-A.md", "0001-a.md.tmp", "../0001-a.md", "0001--a.md", "x.md"):
        assert not is_adr_file_name(bad)


def test_round_trip_and_hash(store: FileStateStore) -> None:
    assert store.adr_sha256() == EMPTY
    sha = store.save_adrs([adr(1, "Use FastAPI"), adr(2, "Use Postgres")])
    assert store.adr_names() == ["0001-use-fastapi.md", "0002-use-postgres.md"]
    docs, loaded_sha = store.load_adrs()
    assert [d.meta.title for d in docs] == ["Use FastAPI", "Use Postgres"]
    assert sha == loaded_sha == store.adr_sha256()
    text = (store.root / "adr" / "0001-use-fastapi.md").read_text(encoding="utf-8")
    assert text.startswith("---\nschema_version: 1\nkind: adr\nid: ADR-0001\n")


def test_any_change_moves_the_hash(store: FileStateStore) -> None:
    first = store.save_adrs([adr(1, "Use FastAPI")])
    path = store.root / "adr" / "0001-use-fastapi.md"
    path.write_text(path.read_text(encoding="utf-8") + "Edited.\n", encoding="utf-8")
    assert store.adr_sha256() != first
    path.rename(store.root / "adr" / "0001-renamed.md")
    assert store.adr_sha256() not in (first, EMPTY)


def test_regenerating_replaces_the_set(store: FileStateStore) -> None:
    store.save_adrs([adr(1, "Old one"), adr(2, "Old two")])
    store.save_adrs([adr(1, "New one")])
    assert store.adr_names() == ["0001-new-one.md"]


def test_other_entries_are_ignored(store: FileStateStore) -> None:
    store.save_adrs([adr(1, "Use FastAPI")])
    before = store.adr_sha256()
    (store.root / "adr" / "notes.txt").write_text("not an ADR", encoding="utf-8")
    (store.root / "adr" / "README.md").write_text("not an ADR", encoding="utf-8")
    assert store.adr_sha256() == before
    assert len(store.load_adrs()[0]) == 1


def test_duplicate_ids_are_refused(store: FileStateStore) -> None:
    with pytest.raises(UsageError):
        store.save_adrs([adr(1, "A"), adr(1, "B")])


def test_a_symlinked_adr_directory_is_refused(store: FileStateStore, tmp_path: Path) -> None:
    elsewhere = tmp_path / "elsewhere"
    elsewhere.mkdir()
    (store.root / "adr").symlink_to(elsewhere)
    with pytest.raises(PolicyViolation):
        store.save_adrs([adr(1, "A")])
    with pytest.raises(PolicyViolation):
        store.load_adrs()
    assert list(elsewhere.iterdir()) == []


def test_an_adr_directory_that_is_a_file_is_refused(store: FileStateStore) -> None:
    (store.root / "adr").write_text("x", encoding="utf-8")
    with pytest.raises(PolicyViolation):
        store.adr_sha256()


def test_a_symlinked_adr_file_is_not_read(store: FileStateStore, tmp_path: Path) -> None:
    store.save_adrs([adr(1, "A")])
    secret = tmp_path / "secret.md"
    secret.write_text("---\nschema_version: 1\nkind: adr\nid: ADR-0002\ntitle: x\n---\n")
    (store.root / "adr" / "0002-x.md").symlink_to(secret)
    with pytest.raises(PolicyViolation):
        store.load_adrs()


def test_adrs_are_sanitized_and_redacted(tmp_path: Path, fake_secrets: FakeSecrets) -> None:
    (tmp_path / ".pm").mkdir()
    store = FileStateStore(tmp_path)  # built after the secrets are in the environment
    token = fake_secrets.values["GITHUB_TOKEN"]
    store.save_adrs([adr(1, "Use \x1b]52;c;eA==\x07 OTP", body=f"Key {token}\u200b here.\n")])
    (name,) = store.adr_names()
    text = (store.root / "adr" / name).read_text(encoding="utf-8")
    assert "\x1b" not in text
    assert "\u200b" not in text
    fake_secrets.assert_absent(text)
    (event,) = store.read_events()
    assert event.kind.value == "injection_signal"


def test_load_with_hash_hashes_the_parsed_bytes(store: FileStateStore) -> None:
    store.save(ApprovalsDoc())
    doc, sha = store.load_with_hash(ArtifactKind.APPROVALS)
    assert isinstance(doc, ApprovalsDoc)
    assert sha == store.sha256(ArtifactKind.APPROVALS)
    with pytest.raises(UsageError):
        store.load_with_hash(ArtifactKind.TASKS)
    with pytest.raises(UsageError):
        store.load_with_hash(ArtifactKind.WORKSHEET)


def test_store_save_refuses_an_adr_as_a_single_file(store: FileStateStore) -> None:
    with pytest.raises(UsageError):
        store.save(adr(1, "A"))


def test_overrides_round_trip_and_stay_out_of_older_files(store: FileStateStore) -> None:
    store.save(ApprovalsDoc())
    assert "overrides" not in (store.root / "approvals.yaml").read_text(encoding="utf-8")
    override = StaleOverride(command="plan", artifact="architecture.md", sha256="a" * 64,
                             reason=OverrideReason.STALE, by="dev",
                             at=datetime(2026, 10, 29, tzinfo=UTC))  # fmt: skip
    store.save(ApprovalsDoc(overrides=[override]))
    loaded = store.load(ArtifactKind.APPROVALS)
    assert isinstance(loaded, ApprovalsDoc)
    assert loaded.overrides == [override]
    assert loaded.approvals == []
    assert not loaded.has(ApprovalGate.G2, "architecture.md", "a" * 64)
