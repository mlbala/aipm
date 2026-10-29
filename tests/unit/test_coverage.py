"""The coverage engine (ARCHITECTURE §8.1): weights, scoring, the clamp and the stop rule."""

import pytest

from aipm.domain.coverage import (
    CLAMP,
    WEIGHTS,
    ProposedStatus,
    StopReason,
    assumption_from_default,
    compute_coverage,
    dimension_score,
    overall,
    proposals_from_scores,
    score_dimensions,
    stop_reason,
)
from aipm.domain.errors import SchemaError
from aipm.domain.ids import next_id
from aipm.domain.models import (
    Answer,
    AnswerSource,
    Assumption,
    Dimension,
    Mode,
    ProjectInfo,
    RequirementsDoc,
)

ALL_COVERED = dict.fromkeys(Dimension, ProposedStatus.COVERED)


def doc(*answers: Answer, assumptions: tuple[Assumption, ...] = ()) -> RequirementsDoc:
    return RequirementsDoc(
        project=ProjectInfo(name="demo"),
        mode=Mode.GREENFIELD,
        answers=list(answers),
        assumptions=list(assumptions),
    )


def answer(dim: Dimension, source: AnswerSource, *, confirmed: bool = True, n: int = 1) -> Answer:
    return Answer(id=f"Q-{n:03d}", dimension=dim, question="q?", answer="a", source=source,
                  confirmed=confirmed)  # fmt: skip


def test_weights_match_the_checklist() -> None:
    assert set(WEIGHTS) == set(Dimension)
    assert sum(WEIGHTS.values()) == 100
    assert WEIGHTS[Dimension.CORE_FEATURES] == 20


def test_an_llm_cannot_mark_coverage_complete_on_its_own() -> None:
    """The mandatory clamp: no user (or confirmed file) answer, no score above 0.5."""
    scores = score_dimensions(doc(), ALL_COVERED)
    assert set(scores.values()) == {CLAMP}
    assert overall(scores) == 0.5


@pytest.mark.parametrize(
    ("source", "confirmed", "expected"),
    [
        (AnswerSource.USER, True, 1.0),
        (AnswerSource.FILE, True, 1.0),
        (AnswerSource.FILE, False, CLAMP),
        (AnswerSource.DEFAULT, True, CLAMP),
    ],
)
def test_evidence_lifts_the_clamp(source: AnswerSource, confirmed: bool, expected: float) -> None:
    d = doc(answer(Dimension.DATA, source, confirmed=confirmed))
    assert score_dimensions(d, ALL_COVERED)[Dimension.DATA] == expected


def test_status_values_and_assumptions() -> None:
    assert dimension_score(ProposedStatus.COVERED, evidence=True, assumed=False) == 1.0
    assert dimension_score(ProposedStatus.PARTIAL, evidence=True, assumed=True) == 0.75
    assert dimension_score(ProposedStatus.MISSING, evidence=True, assumed=True) == 0.75
    assert dimension_score(ProposedStatus.PARTIAL, evidence=True, assumed=False) == 0.5
    assert dimension_score(ProposedStatus.MISSING, evidence=True, assumed=False) == 0.0
    # An assumption alone is not user evidence.
    assert dimension_score(ProposedStatus.MISSING, evidence=False, assumed=True) == CLAMP


def test_unrated_dimensions_count_as_missing_and_the_score_is_weighted() -> None:
    d = doc(answer(Dimension.CORE_FEATURES, AnswerSource.USER))
    coverage = compute_coverage(d, {Dimension.CORE_FEATURES: ProposedStatus.COVERED}, rounds=3)
    assert coverage.rounds == 3
    assert coverage.by_dimension[Dimension.CORE_FEATURES] == 1.0
    assert coverage.by_dimension[Dimension.DATA] == 0.0
    assert coverage.score == 0.2


def test_proposals_from_scores_round_trip() -> None:
    scores = {Dimension.DATA: 1.0, Dimension.USERS_PERSONAS: 0.75, Dimension.CONSTRAINTS: 0.0}
    proposals = proposals_from_scores(scores)
    assert proposals[Dimension.DATA] is ProposedStatus.COVERED
    assert proposals[Dimension.USERS_PERSONAS] is ProposedStatus.PARTIAL
    assert proposals[Dimension.CONSTRAINTS] is ProposedStatus.MISSING
    assert proposals[Dimension.INTEGRATIONS] is ProposedStatus.MISSING


@pytest.mark.parametrize(
    ("kwargs", "expected"),
    [
        ({"user_done": True, "score": 1.0}, StopReason.USER_DONE),
        ({"score": 0.85}, StopReason.THRESHOLD),
        ({"rounds": 6}, StopReason.MAX_ROUNDS),
        ({"has_questions": False}, StopReason.NO_QUESTIONS),
        ({}, None),
    ],
)
def test_stop_rule(kwargs: dict[str, object], expected: StopReason | None) -> None:
    args: dict[str, object] = {
        "score": 0.5, "threshold": 0.85, "rounds": 1, "max_rounds": 6,
        "has_questions": True, "user_done": False,
    }  # fmt: skip
    args.update(kwargs)
    assert stop_reason(**args) is expected  # type: ignore[arg-type]


def test_assumption_from_default() -> None:
    a = assumption_from_default(assumption_id="A-001", dimension=Dimension.DATA,
                                question="Keep data?", default="12 months", reason="r",
                                confirmed=False)  # fmt: skip
    assert a.statement == "12 months (default for: Keep data?)"
    assert not a.confirmed
    long = assumption_from_default(assumption_id="A-002", dimension=Dimension.DATA,
                                   question="q" * 300, default="d" * 600, reason="r" * 400,
                                   confirmed=True)  # fmt: skip
    assert len(long.statement) <= 500
    assert len(long.reason) <= 300


def test_next_id() -> None:
    assert next_id("question", []) == "Q-001"
    assert next_id("question", ["Q-002", "Q-010", "A-050", "junk"]) == "Q-011"
    assert next_id("assumption", ["A-009"]) == "A-010"
    with pytest.raises(SchemaError, match="no question IDs left after Q-999"):
        next_id("question", ["Q-999"])
    with pytest.raises(ValueError, match="no sequential IDs"):
        next_id("task", [])
