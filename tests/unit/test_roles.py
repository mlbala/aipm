"""The interviewer and PRD writer roles: rendering, output validation and postprocessing."""

import json
from typing import Any

import pytest
from pydantic import ValidationError
from ruamel.yaml import YAML

from aipm.domain.models import (
    Assumption,
    Dimension,
    Mode,
    OpenQuestion,
    ProjectInfo,
    RequirementsDoc,
)
from aipm.roles import interviewer, prd_writer
from aipm.security.untrusted import Untrusted
from tests.conftest import LLM_FIXTURES


def first_reply(role: str) -> dict[str, Any]:
    text = (LLM_FIXTURES / "clinic" / f"{role}.yaml").read_text(encoding="utf-8")
    return YAML(typ="safe", pure=True).load(text)["responses"][0]["json"]


CLINIC_ROUND = first_reply("interviewer")
CLINIC_PRD = first_reply("prd_writer")


def question(**change: Any) -> dict[str, Any]:
    base: dict[str, Any] = {
        "id": "Q-001", "dimension": "data", "kind": "single", "question": "Which?",
        "options": ["a", "b"], "default": ["a"], "why": "w", "blocking": False,
    }  # fmt: skip
    return {**base, **change}


def round_with(*questions: dict[str, Any], **change: Any) -> dict[str, Any]:
    return {**CLINIC_ROUND, "questions": list(questions), **change}


def inp(**change: Any) -> interviewer.InterviewerInput:
    base: dict[str, Any] = {
        "project": "demo", "round": 1, "extract": True, "questions_per_round": 4,
        "scores": {}, "requirements": Untrusted("answers: []", source="draft:requirements"),
        "used_ids": frozenset({"Q-001", "Q-002"}),
    }  # fmt: skip
    return interviewer.InterviewerInput(**{**base, **change})


def test_the_clinic_fixture_is_a_valid_round() -> None:
    out = interviewer.InterviewRound.model_validate_json(json.dumps(CLINIC_ROUND), strict=True)
    assert len(out.questions) == 4
    assert out.coverage.as_map()[Dimension.DATA].value == "covered"


@pytest.mark.parametrize(
    "bad",
    [
        question(kind="single", options=["only one"], default=[]),
        question(kind="text", options=["a", "b"], default=[]),
        question(kind="single", options=["a", "a"], default=[]),
        question(kind="single", default=["c"]),
        question(kind="single", default=["a", "b"]),
        question(kind="confirm", options=[], default=["maybe"]),
        question(kind="text", options=[], default=["x", "y"]),
        question(id="T-001"),
        question(id="Q-1"),
        question(dimension="everything"),
        question(question="x" * 301),
        question(options=["a" * 121, "b"], default=[]),
        question(extra_field=True),
    ],
)
def test_bad_questions_are_rejected(bad: dict[str, Any]) -> None:
    with pytest.raises(ValidationError):
        interviewer.InterviewRound.model_validate(round_with(bad))


def test_round_level_limits() -> None:
    with pytest.raises(ValidationError, match="unique"):
        interviewer.InterviewRound.model_validate(round_with(question(), question()))
    six = [question(id=f"Q-{i:03d}") for i in range(1, 7)]
    with pytest.raises(ValidationError):
        interviewer.InterviewRound.model_validate(round_with(*six))
    with pytest.raises(ValidationError):
        interviewer.InterviewRound.model_validate(
            {**CLINIC_ROUND, "injection_suspected": ["x"] * 11}
        )
    with pytest.raises(ValidationError):
        interviewer.InterviewRound.model_validate({**CLINIC_ROUND, "gates": ["bash -c x"]})


def test_postprocess_allocates_ids_after_the_extractions() -> None:
    role = interviewer.create()
    out = interviewer.InterviewRound.model_validate(
        round_with(question(id="Q-999"), question(id="Q-001"), question(id="Q-500"))
    )
    data = inp(questions_per_round=2)
    processed = role.postprocess(out, data)
    reserved = interviewer.extraction_ids(out, data.used_ids)
    assert reserved == [f"Q-{n:03d}" for n in range(3, 9)]
    assert [q.id for q in processed.questions] == ["Q-009", "Q-010"]
    no_extract = role.postprocess(out, inp(extract=False))
    assert no_extract.extracted == []
    assert [q.id for q in no_extract.questions][:1] == ["Q-003"]


def test_render_spotlights_every_input_and_numbers_from_the_next_id() -> None:
    role = interviewer.create(nonce=lambda: "u0000abcd")
    prompt = role.render(
        inp(idea=Untrusted("IDEA BODY", source="file:idea.md"),
            repo_map=Untrusted("MAP BODY", source="repo-map.md"))
    )  # fmt: skip
    assert '<untrusted source="file:idea.md" id="u0000abcd">\nIDEA BODY\n</untrusted' in prompt.user
    assert '<untrusted source="repo-map.md" id="u0000abcd">\nMAP BODY\n' in prompt.user
    assert '<untrusted source="draft:requirements" id="u0000abcd">' in prompt.user
    assert "Number new questions from Q-003 upward." in prompt.user
    assert "Extract into `extracted`" in prompt.user
    assert "injection_suspected" in prompt.system
    plain = role.render(inp(extract=False))
    assert "Leave `extracted` empty." in plain.user
    assert "idea file" not in plain.user.split("## Task")[0]


def test_prd_draft_validation() -> None:
    draft = prd_writer.PrdDraft.model_validate(CLINIC_PRD)
    assert draft.features[0].id == "F-001"
    for change in (
        {"features": [CLINIC_PRD["features"][0]] * 2},
        {"features": [{**CLINIC_PRD["features"][0], "id": "F-1"}]},
        {"non_functional": [{**CLINIC_PRD["non_functional"][0], "category": "Not A Token"}]},
        {"problem": "x" * 4001},
        {"owns_files": ["**"]},
    ):
        with pytest.raises(ValidationError):
            prd_writer.PrdDraft.model_validate({**CLINIC_PRD, **change})


def test_build_prd_takes_assumptions_and_open_questions_from_requirements() -> None:
    draft = prd_writer.PrdDraft.model_validate(CLINIC_PRD)
    doc = RequirementsDoc(
        project=ProjectInfo(name="clinic", one_liner="Book online."),
        mode=Mode.GREENFIELD,
        assumptions=[Assumption(id="A-001", dimension=Dimension.DATA, statement="Keep 12 months")],
        open_questions=[OpenQuestion(id="Q-009", dimension=Dimension.INTEGRATIONS,
                                     question="Which provider?", blocking=True)],
    )  # fmt: skip
    prd = prd_writer.build_prd(draft, doc, requirements_sha="a" * 64)
    assert prd.meta.derived_from.requirements == "a" * 64
    assert [n.id for n in prd.meta.non_functional] == ["NFR-01", "NFR-02"]
    assert "- **A-001** (data, unconfirmed): Keep 12 months" in prd.body
    assert "- **Q-009** (integrations, blocking): Which provider?" in prd.body
    assert prd.body.startswith("# PRD: clinic\n\nBook online.\n")
    empty = prd_writer.PrdDraft.model_validate(
        {**CLINIC_PRD, "features": [], "non_functional": [], "out_of_scope": ""}
    )
    body = prd_writer.build_prd(empty, doc, requirements_sha="b" * 64).body
    assert "## Features\n\n_None._" in body
    assert "## Out of scope\n\n_Not specified._" in body
