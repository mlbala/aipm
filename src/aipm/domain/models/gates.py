"""The gate menu entries and the prepare step, as copied from a stack template (§13.1).

These models check shape only. `aipm.security.command_policy` decides whether an argv may run.
"""

from enum import StrEnum
from typing import Annotated, Literal, Self

from pydantic import Field, StringConstraints, model_validator

from aipm.domain.models.base import Severity, StrictModel

MAX_ARGV = 32
MAX_ARG_LENGTH = 512

ArgvElement = Annotated[
    str, StringConstraints(min_length=1, max_length=MAX_ARG_LENGTH, strip_whitespace=False)
]
"""One argv element, kept exactly as written (whitespace is meaningful in argv)."""
ArgvList = Annotated[tuple[ArgvElement, ...], Field(min_length=1, max_length=MAX_ARGV)]


class BuiltinGate(StrEnum):
    """Gates implemented inside aipm rather than by a configured argv (§13.3)."""

    GITLEAKS = "gitleaks"
    SEMGREP = "semgrep"
    OSV = "osv"
    AC_TRACE = "ac_trace"
    AC_REVIEW = "ac_review"


class NetworkProfile(StrEnum):
    """Network access for a sandboxed process (SECURITY.md §9.1)."""

    NONE = "none"
    REGISTRIES = "registries"
    API_ONLY = "api-only"


class GateDef(StrictModel):
    """One gate from the trusted menu: a configured argv, or a built-in gate."""

    run: ArgvList | None = None
    builtin: BuiltinGate | None = None
    required: bool = False
    fail_on: Severity | None = None
    mode: Literal["veto"] | None = None

    @model_validator(mode="after")
    def _one_kind(self) -> Self:
        if (self.run is None) == (self.builtin is None):
            raise ValueError("a gate has exactly one of 'run' and 'builtin'")
        if self.fail_on is not None and self.builtin is None:
            raise ValueError("'fail_on' applies to built-in gates only")
        if self.mode is not None and self.builtin is not BuiltinGate.AC_REVIEW:
            raise ValueError("'mode' applies to the ac_review gate only")
        return self


class PrepareDef(StrictModel):
    """The prepare step: the only place package installation is allowed (SECURITY.md §10)."""

    run: ArgvList
    network: NetworkProfile = NetworkProfile.REGISTRIES
