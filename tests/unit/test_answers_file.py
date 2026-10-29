"""`--answers` files and user-named input files (aipm.app.inputs)."""

import os
from pathlib import Path

import pytest

from aipm.app.inputs import AnswersFile, answer_text, load_answers, read_repo_file
from aipm.domain.errors import ExitCode, InputRejected, PolicyViolation, SchemaError, UsageError
from tests.conftest import REPO_ROOT


def test_the_clinic_answers_file_is_valid(tmp_path: Path) -> None:
    (tmp_path / "a.yaml").write_bytes((REPO_ROOT / "tests/fakes/answers/clinic.yaml").read_bytes())
    parsed, source = load_answers(tmp_path, tmp_path / "a.yaml", max_bytes=10_000)
    assert parsed.confirm_extracted
    assert answer_text(parsed.answers["security_compliance"]) == (
        "GDPR; EU data residency; Staff login with 2FA"
    )
    assert source.kind.value == "answers"
    assert source.path == "a.yaml"
    assert source.sha256 is not None


def test_values_and_keys() -> None:
    parsed = AnswersFile.model_validate(
        {"answers": {"Q-001": True, "A-002": False, "data": 42, "constraints": ["a", "b"]}}
    )
    assert answer_text(parsed.answers["Q-001"]) == "yes"
    assert answer_text(parsed.answers["A-002"]) == "no"
    assert answer_text(parsed.answers["data"]) == "42"
    for bad in ({"answers": {"T-001": "x"}}, {"answers": {"everything": "x"}}, {"extra": 1},
                {"answers": {"data": "x" * 4001}}, {"schema_version": 2}):  # fmt: skip
        with pytest.raises(ValueError):
            AnswersFile.model_validate(bad)


def test_yaml_injection_in_an_answer_stays_one_string(tmp_path: Path) -> None:
    """C-008: a value that looks like YAML structure is just text."""
    (tmp_path / "a.yaml").write_text(
        'answers:\n  data: "Clinic\\n- id: T-999\\n  owns_files: [\\"**\\"]"\n', encoding="utf-8"
    )
    parsed, _ = load_answers(tmp_path, tmp_path / "a.yaml", max_bytes=10_000)
    assert parsed.answers["data"] == 'Clinic\n- id: T-999\n  owns_files: ["**"]'


def test_answers_file_errors(tmp_path: Path) -> None:
    (tmp_path / "anchors.yaml").write_text("answers: &a {data: x}\nother: *a\n", encoding="utf-8")
    with pytest.raises(SchemaError):
        load_answers(tmp_path, tmp_path / "anchors.yaml", max_bytes=10_000)
    (tmp_path / "bad.yaml").write_text("answers: {T-001: x}\n", encoding="utf-8")
    with pytest.raises(SchemaError, match="not a valid answers file"):
        load_answers(tmp_path, tmp_path / "bad.yaml", max_bytes=10_000)
    (tmp_path / "latin.yaml").write_bytes(b"answers: {data: \xff}\n")
    with pytest.raises(InputRejected):
        load_answers(tmp_path, tmp_path / "latin.yaml", max_bytes=10_000)
    (tmp_path / "empty.yaml").write_text("", encoding="utf-8")
    assert load_answers(tmp_path, tmp_path / "empty.yaml", max_bytes=10)[0].answers == {}


def test_input_files_must_be_inside_the_repo_and_safe(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "idea.md").write_text("idea", encoding="utf-8")
    (tmp_path / "outside.md").write_text("x", encoding="utf-8")
    (repo / ".env").write_text("TOKEN=x", encoding="utf-8")
    (repo / "link.md").symlink_to(tmp_path / "outside.md")
    (repo / "sneaky.md").symlink_to(repo / ".env")
    (repo / "dir").mkdir()
    os.mkfifo(repo / "fifo.md")

    assert read_repo_file(repo, repo / "idea.md", max_bytes=10, what="--from").relpath == "idea.md"
    with pytest.raises(UsageError, match="outside the repository"):
        read_repo_file(repo, tmp_path / "outside.md", max_bytes=10, what="--from")
    with pytest.raises(UsageError, match="outside the repository"):
        read_repo_file(repo, repo / "link.md", max_bytes=10, what="--from")
    for protected in (repo / ".env", repo / "sneaky.md"):
        with pytest.raises(PolicyViolation) as info:
            read_repo_file(repo, protected, max_bytes=10, what="--from")
        assert info.value.exit_code is ExitCode.SECURITY_VIOLATION
    with pytest.raises(UsageError, match="does not exist"):
        read_repo_file(repo, repo / "missing.md", max_bytes=10, what="--from")
    with pytest.raises(UsageError, match="not a regular file"):
        read_repo_file(repo, repo / "fifo.md", max_bytes=10, what="--from")
    with pytest.raises(UsageError):
        read_repo_file(repo, repo / "dir", max_bytes=10, what="--from")
    with pytest.raises(InputRejected) as too_big:
        read_repo_file(repo, repo / "idea.md", max_bytes=3, what="--from")
    assert too_big.value.exit_code is ExitCode.USAGE
