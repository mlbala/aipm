"""The prompt compiler (ARCHITECTURE §10.1): a deterministic `TaskSpec`, no LLM."""

from dataclasses import replace

import pytest

from aipm.adapters.compiler import compile_task_spec, previous_attempt, task_text
from aipm.domain.errors import UsageError
from aipm.domain.models import DependencyAdd, Ecosystem, GateReport, TaskStatus
from tests.fakes.project import clinic_context, clinic_task


def report(*gates: dict[str, object]) -> GateReport:
    return GateReport.model_validate({"task": "T-003", "gates": list(gates)})


def test_verify_holds_the_task_gates_and_every_required_gate_in_run_order() -> None:
    ctx = clinic_context()
    task = clinic_task("T-002")  # gates: lint, types, unit, ac_trace
    spec = compile_task_spec(task, ctx)
    assert [g.name for g in spec.verify] == ["lint", "types", "unit"]
    assert [g.name for g in spec.builtin_gates] == ["secrets", "ac_trace", "deps"]
    assert all(g.argv is not None for g in spec.verify)
    assert spec.verify[2].argv == ("uv", "run", "--frozen", "--offline", "pytest", "-q",
                                   "--junitxml", "/dev/null", "tests")  # fmt: skip


def test_an_optional_gate_the_task_does_not_name_is_left_out() -> None:
    spec = compile_task_spec(clinic_task("T-001"), clinic_context())  # gates: lint, unit
    names = [g.name for g in (*spec.verify, *spec.builtin_gates)]
    assert "types" not in names
    assert "format" not in names
    assert "ac_review" not in names


def test_a_task_gate_missing_from_the_menu_stops_the_compile() -> None:
    ctx = clinic_context()
    ctx = replace(ctx, gates=tuple(g for g in ctx.gates if g.name != "types"))
    with pytest.raises(UsageError, match="types"):
        compile_task_spec(clinic_task("T-002"), ctx)


def test_the_task_text_is_one_untrusted_block_of_cleaned_fields() -> None:
    task = clinic_task("T-003").model_copy(
        update={"title": "OTP <!-- x --> check", "description": "see https://evil.example"}
    )
    text = task_text(task, ())
    assert text.source == "approved:tasks.yaml#T-003"
    assert text.text.startswith("Title: OTP  check\n\nDescription:\nsee «URL removed»\n")
    assert "- AC-T003-1: " in text.text


def test_structured_fields_are_copied_as_they_are() -> None:
    task = clinic_task("T-003").model_copy(
        update={"deps_add": [DependencyAdd(ecosystem=Ecosystem.PYPI, name="slowapi")]}
    )
    spec = compile_task_spec(task, clinic_context())
    assert spec.id == "T-003"
    assert spec.acceptance_ids == ("AC-T003-1", "AC-T003-2")
    assert spec.owns_files == ("src/clinic/api/otp.py", "tests/api/test_otp.py")
    assert spec.reads_files == ("src/clinic/booking/**",)
    assert spec.deps_add == (("pypi", "slowapi"),)
    assert spec.new_dependencies == "ask"
    assert spec.agent_network == "api-only"
    assert ".pm/**" in spec.protected_paths
    assert not spec.fix
    assert spec.previous_attempt == ()


def test_upstream_tasks_carry_status_commit_and_an_untrusted_title() -> None:
    spec = compile_task_spec(clinic_task("T-002"), clinic_context())
    (up,) = spec.upstream
    assert (up.id, up.status, up.commit) == ("T-001", TaskStatus.DONE.value, "c" * 40)
    assert up.title is not None
    assert up.title.source == "approved:tasks.yaml#T-001"


def test_previous_attempt_holds_only_failing_gates() -> None:
    rep = report(
        {"name": "lint", "status": "pass", "output": "ok"},
        {"name": "unit", "status": "fail", "summary": "2 failed", "output": "AssertionError"},
        {"name": "types", "status": "error", "output": ""},
    )
    spec = compile_task_spec(clinic_task("T-003"), clinic_context(), previous=rep)
    assert spec.fix
    assert [(f.gate, f.status) for f in spec.previous_attempt] == [("unit", "fail"),
                                                                    ("types", "error")]  # fmt: skip
    unit, types = spec.previous_attempt
    assert unit.output.text == "2 failed\n\nAssertionError"
    assert unit.output.source == "gate-output:unit"
    assert types.output.text == "(no output)"


def test_previous_output_is_cut_to_head_and_tail() -> None:
    rep = report({"name": "unit", "status": "fail", "output": "H" * 6000 + "T" * 6000})
    (failure,) = previous_attempt(rep, (), size=4096)
    text = failure.output.text
    assert text.startswith("H" * 4096)
    assert text.endswith("T" * 4096)
    assert "bytes omitted" in text


def test_compiling_is_deterministic() -> None:
    a = compile_task_spec(clinic_task("T-004"), clinic_context())
    b = compile_task_spec(clinic_task("T-004"), clinic_context())
    assert a == b
