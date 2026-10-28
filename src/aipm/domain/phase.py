"""Phase derivation from `.pm/` files (C-4, ARCHITECTURE §7.1). Pure."""

from dataclasses import dataclass

from aipm.domain.models import ArtifactKind, Phase, StateSnapshot


@dataclass(frozen=True, slots=True)
class PhaseReport:
    """The current phase and what to do next."""

    phase: Phase
    stale: list[ArtifactKind]
    next_command: str | None
    blockers: list[str]


def derive_phase(snapshot: StateSnapshot) -> PhaseReport:
    """Walk the artifacts in order and return the first missing, unapproved or stale step."""
    raise NotImplementedError("v0.1: build prompt 04")
