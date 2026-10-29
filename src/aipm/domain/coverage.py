"""Discovery coverage: checklist scoring, assumptions and the stop rule (C-7, ARCHITECTURE §8).

The interviewer LLM proposes a status per dimension. This module turns the proposals into scores
deterministically and applies the mandatory clamp: a dimension scores at most 0.5 unless it has an
answer with `source: user`, or a confirmed `source: file` answer. An LLM therefore cannot mark
coverage complete on its own, whatever an idea file tells it to do. Pure: no I/O.
"""

from collections.abc import Iterable, Mapping
from enum import StrEnum

from aipm.domain.models import (
    Answer,
    AnswerSource,
    Assumption,
    Coverage,
    Dimension,
    RequirementsDoc,
)

WEIGHTS: Mapping[Dimension, int] = {
    Dimension.PROBLEM_GOALS: 15,
    Dimension.USERS_PERSONAS: 10,
    Dimension.CORE_FEATURES: 20,
    Dimension.DATA: 10,
    Dimension.INTEGRATIONS: 8,
    Dimension.SCALE_PERFORMANCE: 8,
    Dimension.SECURITY_COMPLIANCE: 10,
    Dimension.DEPLOYMENT_OPS: 7,
    Dimension.CONSTRAINTS: 5,
    Dimension.SUCCESS_METRICS: 7,
}
"""ARCHITECTURE §8.1; the weights sum to 100."""

NEEDS: Mapping[Dimension, str] = {
    Dimension.PROBLEM_GOALS: "Problem statement and at least one measurable goal",
    Dimension.USERS_PERSONAS: "At least one user type, with its main job to be done",
    Dimension.CORE_FEATURES: "At least three features, with must/should priority",
    Dimension.DATA: "Main entities, retention, and PII presence",
    Dimension.INTEGRATIONS: 'External systems, or an explicit "none"',
    Dimension.SCALE_PERFORMANCE: 'Expected load and latency target, or an explicit "small"',
    Dimension.SECURITY_COMPLIANCE: (
        'Auth model, data sensitivity, region/compliance, or explicit "none"'
    ),
    Dimension.DEPLOYMENT_OPS: "Target environment and environments needed",
    Dimension.CONSTRAINTS: "Budget, timeline, mandated technology",
    Dimension.SUCCESS_METRICS: "How success is measured after launch",
}
"""What covers each dimension (ARCHITECTURE §8.1)."""

COVERED = 1.0
ASSUMED = 0.75
PARTIAL = 0.5
MISSING = 0.0
CLAMP = 0.5
"""The most a dimension can score without user evidence."""


class ProposedStatus(StrEnum):
    """The interviewer's view of one dimension."""

    COVERED = "covered"
    PARTIAL = "partial"
    MISSING = "missing"


class StopReason(StrEnum):
    """Why the interview stopped (ARCHITECTURE §8.2 step 3)."""

    THRESHOLD = "threshold"
    MAX_ROUNDS = "max_rounds"
    NO_QUESTIONS = "no_questions"
    USER_DONE = "user_done"


def has_evidence(answers: Iterable[Answer], dimension: Dimension) -> bool:
    """An answer from the user, or a confirmed answer from a file, in this dimension."""
    return any(
        a.dimension is dimension
        and (a.source is AnswerSource.USER or (a.source is AnswerSource.FILE and a.confirmed))
        for a in answers
    )


def dimension_score(proposed: ProposedStatus, *, evidence: bool, assumed: bool) -> float:
    """One dimension's score: covered 1.0, assumed 0.75, partial 0.5, missing 0, then clamped."""
    if proposed is ProposedStatus.COVERED:
        score = COVERED
    elif assumed:
        score = ASSUMED
    elif proposed is ProposedStatus.PARTIAL:
        score = PARTIAL
    else:
        score = MISSING
    return score if evidence else min(score, CLAMP)


def score_dimensions(
    doc: RequirementsDoc, proposed: Mapping[Dimension, ProposedStatus]
) -> dict[Dimension, float]:
    """Every dimension's clamped score; a dimension the LLM did not rate counts as missing."""
    assumed = {a.dimension for a in doc.assumptions}
    return {
        dim: dimension_score(
            proposed.get(dim, ProposedStatus.MISSING),
            evidence=has_evidence(doc.answers, dim),
            assumed=dim in assumed,
        )
        for dim in Dimension
    }


def overall(scores: Mapping[Dimension, float]) -> float:
    """The weighted mean, rounded to two decimals."""
    total = sum(WEIGHTS.values())
    return round(sum(WEIGHTS[d] * scores.get(d, 0.0) for d in Dimension) / total, 2)


def compute_coverage(
    doc: RequirementsDoc, proposed: Mapping[Dimension, ProposedStatus], *, rounds: int
) -> Coverage:
    """The `coverage` block of requirements.yaml."""
    scores = score_dimensions(doc, proposed)
    return Coverage(score=overall(scores), rounds=rounds, by_dimension=scores)


def proposals_from_scores(
    by_dimension: Mapping[Dimension, float],
) -> dict[Dimension, ProposedStatus]:
    """Recover proposals from stored scores, to rescore after an edit without an LLM call."""
    result: dict[Dimension, ProposedStatus] = {}
    for dim in Dimension:
        score = by_dimension.get(dim, 0.0)
        if score >= COVERED:
            result[dim] = ProposedStatus.COVERED
        elif score >= PARTIAL:
            result[dim] = ProposedStatus.PARTIAL
        else:
            result[dim] = ProposedStatus.MISSING
    return result


def stop_reason(
    *,
    score: float,
    threshold: float,
    rounds: int,
    max_rounds: int,
    has_questions: bool,
    user_done: bool,
) -> StopReason | None:
    """The first stop condition that holds, or None to ask another round."""
    if user_done:
        return StopReason.USER_DONE
    if score >= threshold:
        return StopReason.THRESHOLD
    if rounds >= max_rounds:
        return StopReason.MAX_ROUNDS
    if not has_questions:
        return StopReason.NO_QUESTIONS
    return None


def assumption_from_default(
    *,
    assumption_id: str,
    dimension: Dimension,
    question: str,
    default: str,
    reason: str,
    confirmed: bool,
) -> Assumption:
    """A written assumption for a default the user accepted (P-4)."""
    suffix = f" (default for: {question})"
    room = 500 - len(suffix)
    statement = default if room < 40 else default[:room] + suffix
    return Assumption(
        id=assumption_id,
        dimension=dimension,
        statement=statement[:500],
        reason=reason[:300],
        confirmed=confirmed,
    )
