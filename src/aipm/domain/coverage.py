"""Discovery coverage: checklist scoring, assumptions, open questions, stop rule (C-7, §8)."""

from aipm.domain.models import StateSnapshot


def coverage_score(snapshot: StateSnapshot) -> float:
    """Return the weighted coverage of the requirements checklist, from 0 to 1."""
    raise NotImplementedError("v0.1: build prompt 03")
