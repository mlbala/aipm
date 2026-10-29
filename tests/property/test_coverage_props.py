"""Property: whatever the LLM proposes, no dimension scores above 0.5 without user evidence."""

from hypothesis import given
from hypothesis import strategies as st

from aipm.domain.coverage import CLAMP, ProposedStatus, compute_coverage
from aipm.domain.models import (
    Answer,
    AnswerSource,
    Assumption,
    Dimension,
    Mode,
    ProjectInfo,
    RequirementsDoc,
)

dimensions = st.sampled_from(list(Dimension))
proposals = st.dictionaries(dimensions, st.sampled_from(list(ProposedStatus)))
non_evidence = st.one_of(
    st.just((AnswerSource.FILE, False)), st.just((AnswerSource.DEFAULT, True)),
    st.just((AnswerSource.DEFAULT, False)),
)  # fmt: skip


@given(
    proposed=proposals,
    answers=st.lists(st.tuples(dimensions, non_evidence), max_size=20),
    assumed=st.lists(dimensions, max_size=10),
)
def test_no_evidence_means_clamped(
    proposed: dict[Dimension, ProposedStatus],
    answers: list[tuple[Dimension, tuple[AnswerSource, bool]]],
    assumed: list[Dimension],
) -> None:
    doc = RequirementsDoc(
        project=ProjectInfo(name="demo"),
        mode=Mode.GREENFIELD,
        answers=[
            Answer(
                id=f"Q-{i + 1:03d}", dimension=d, question="q", answer="a", source=src, confirmed=ok
            )
            for i, (d, (src, ok)) in enumerate(answers)
        ],
        assumptions=[
            Assumption(id=f"A-{i + 1:03d}", dimension=d, statement="s")
            for i, d in enumerate(assumed)
        ],
    )
    coverage = compute_coverage(doc, proposed, rounds=1)
    assert all(score <= CLAMP for score in coverage.by_dimension.values())
    assert coverage.score <= CLAMP
