"""The gate menu entries and the prepare step, as copied from a stack template (§13.1).

These models check shape only. `aipm.security.command_policy` decides whether an argv may run.
"""

from enum import StrEnum
from typing import Annotated, Literal, Self

from pydantic import Field, StringConstraints, model_validator

from aipm.domain.models.artifacts import GateName
from aipm.domain.models.base import Severity, Str1000, StrictModel, TaskId

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


class GateStatus(StrEnum):
    """The outcome of one gate (ARCHITECTURE §13.2)."""

    PASS = "pass"  # noqa: S105 - a gate status, not a password
    FAIL = "fail"
    ERROR = "error"
    SKIPPED = "skipped"


MAX_GATE_OUTPUT = 1_048_576
GateOutput = Annotated[str, StringConstraints(max_length=MAX_GATE_OUTPUT, strip_whitespace=False)]
"""A gate's output, kept as written (T2: it comes from programs that ran agent code)."""


class GateResult(StrictModel):
    """One gate's result. `output` is the captured output, cut to head and tail in prompts."""

    name: GateName
    status: GateStatus
    duration_ms: Annotated[int, Field(ge=0, le=86_400_000)] = 0
    summary: Str1000 = ""
    output: GateOutput = ""


class GateReport(StrictModel):
    """The gate results of one `verify` of one task (§13.2). `aipm prompt --fix` reads a saved
    one; `verify` writes them from v0.2 on. Every string in it is T2."""

    schema_version: Literal[1] = 1
    task: TaskId
    gates: list[GateResult] = Field(default_factory=list[GateResult], max_length=32)

    def failures(self) -> list[GateResult]:
        """The gates that failed or errored, in report order."""
        return [g for g in self.gates if g.status in (GateStatus.FAIL, GateStatus.ERROR)]
