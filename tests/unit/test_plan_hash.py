"""G3 approves the plan, not task progress (ADR-0016), and the gate report model (§13.2)."""

from datetime import UTC, datetime
from pathlib import Path

import pytest
from pydantic import ValidationError

from aipm.app.snapshot import read_snapshot
from aipm.domain.models import (
    ArtifactKind,
    Blocked,
    BlockedReason,
    Done,
    GateReport,
    TasksDoc,
    TaskStatus,
)
from aipm.state.store import normalized_sha256, open_store, plan_sha256
from aipm.state.yamlio import dump_yaml
from tests.golden.test_design_plan_golden import tasks_doc


def test_plan_view_resets_progress_only() -> None:
    doc = tasks_doc()
    at = datetime(2026, 10, 29, tzinfo=UTC)
    doc.tasks[0] = doc.tasks[0].model_copy(update={
        "status": TaskStatus.DONE, "done": Done(commit="c" * 40, at=at), "attempts": 2,
        "base_sha": "d" * 40})  # fmt: skip
    doc.tasks[1] = doc.tasks[1].model_copy(update={
        "status": TaskStatus.BLOCKED, "blocked": Blocked(reason=BlockedReason.MANUAL)})  # fmt: skip
    view = doc.plan_view()
    assert view.tasks == tasks_doc().tasks
    assert plan_sha256(doc, "f" * 64) == canonical(tasks_doc())


def canonical(doc: TasksDoc) -> str:
    return normalized_sha256(dump_yaml(doc.to_document()).encode("utf-8"))


def test_an_unstarted_plan_is_pinned_to_its_exact_bytes() -> None:
    # A comment or a formatting change in an unstarted plan still voids G3 (the file hash).
    assert plan_sha256(tasks_doc(), "f" * 64) == "f" * 64


def test_changing_a_started_plan_changes_its_hash() -> None:
    doc = tasks_doc()
    started = [doc.tasks[0].model_copy(update={"status": TaskStatus.IN_PROGRESS,
                                                "base_sha": "e" * 40}), *doc.tasks[1:]]  # fmt: skip
    edited = [started[0].model_copy(update={"title": "Something else"}), *started[1:]]
    before = plan_sha256(doc.model_copy(update={"tasks": started}), "f" * 64)
    after = plan_sha256(doc.model_copy(update={"tasks": edited}), "f" * 64)
    assert before == canonical(doc)
    assert after != before


def test_the_snapshot_pins_the_plan_hash(tmp_repo: Path) -> None:
    store = open_store(tmp_repo)
    doc = tasks_doc()
    file_sha = store.save(doc)
    started = doc.model_copy(update={"tasks": [doc.tasks[0].model_copy(update={
        "status": TaskStatus.IN_PROGRESS, "base_sha": "e" * 40}), *doc.tasks[1:]]})  # fmt: skip
    assert store.save(started) != file_sha
    snapshot, _ = read_snapshot(store, coverage_threshold=1.0, trusted=False)
    assert snapshot.hashes[ArtifactKind.TASKS] == file_sha


def test_gate_report() -> None:
    report = GateReport.model_validate({"task": "T-001", "gates": [
        {"name": "lint", "status": "pass"},
        {"name": "unit", "status": "fail", "output": "  keep  \n  spacing\n"},
        {"name": "types", "status": "error"}, {"name": "sast", "status": "skipped"}]})  # fmt: skip
    assert [g.name for g in report.failures()] == ["unit", "types"]
    assert report.gates[1].output == "  keep  \n  spacing\n"
    for bad in ({"task": "T-001", "extra": 1}, {"task": "T1"},
                {"task": "T-001", "gates": [{"name": "Bad Name", "status": "fail"}]},
                {"task": "T-001", "gates": [{"name": "unit", "status": "maybe"}]}):  # fmt: skip
        with pytest.raises(ValidationError):
            GateReport.model_validate(bad)
