"""Shared pieces of the `.pm/` schemas: the strict base model, field types and artifact bases.

Every model forbids extra keys, strips surrounding whitespace, bounds every string and list,
and hides input values in validation errors, so an error message never echoes a secret.
"""

from enum import StrEnum
from typing import Annotated, ClassVar, Literal, NewType

from pydantic import AfterValidator, BaseModel, ConfigDict, StringConstraints

from aipm.domain.errors import PolicyViolation
from aipm.domain.ids import ID_PATTERNS
from aipm.security.paths import normalize_relpath, safe_rel_glob

SCHEMA_VERSION = 1
"""The newest `schema_version` this aipm reads and writes (ARCHITECTURE §6.2)."""


class ArtifactKind(StrEnum):
    """The kinds of `.pm/` artifact (ARCHITECTURE §6.1)."""

    CONFIG = "config"
    REQUIREMENTS = "requirements"
    PRD = "prd"
    ARCHITECTURE = "architecture"
    ADR = "adr"
    THREAT_MODEL = "threat_model"
    TASKS = "tasks"
    WORKSHEET = "worksheet"
    APPROVALS = "approvals"
    REPO_MAP = "repo_map"


class Phase(StrEnum):
    """Project phases (ARCHITECTURE §7.1)."""

    UNINITIALIZED = "uninitialized"
    INITIALIZED = "initialized"
    DISCOVERING = "discovering"
    REQUIREMENTS_READY = "requirements_ready"
    PRD_DRAFT = "prd_draft"
    PRD_APPROVED = "prd_approved"
    DESIGN_DRAFT = "design_draft"
    DESIGN_APPROVED = "design_approved"
    PLAN_DRAFT = "plan_draft"
    PLAN_APPROVED = "plan_approved"
    BUILDING = "building"
    BUILT = "built"


class RoleName(StrEnum):
    """LLM roles (ARCHITECTURE §14.1)."""

    INTERVIEWER = "interviewer"
    PRD_WRITER = "prd_writer"
    ARCHITECT = "architect"
    THREAT_MODELER = "threat_modeler"
    PLANNER = "planner"
    AC_REVIEWER = "ac_reviewer"


class ToolName(StrEnum):
    """Coding tools with an adapter (ARCHITECTURE §11)."""

    CLAUDE = "claude"
    CODEX = "codex"
    COPILOT = "copilot"
    GEMINI = "gemini"


class Severity(StrEnum):
    """Threat and finding severity, lowest first."""

    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


RepoId = NewType("RepoId", str)
"""First 16 hex characters of sha256(realpath(repo_root)) (ARCHITECTURE §6.1)."""


class StrictModel(BaseModel):
    """The base of every schema: extra keys forbidden, inputs never echoed in errors."""

    model_config = ConfigDict(
        extra="forbid",
        str_strip_whitespace=True,
        validate_assignment=True,
        hide_input_in_errors=True,
    )


def _id(kind: str) -> StringConstraints:
    return StringConstraints(pattern=rf"^{ID_PATTERNS[kind]}$")


def _glob(value: str) -> str:
    try:
        return safe_rel_glob(value)
    except PolicyViolation as exc:
        raise ValueError(exc.message) from None


def _relpath(value: str) -> str:
    try:
        return normalize_relpath(value)
    except PolicyViolation as exc:
        raise ValueError(exc.message) from None


def _text(max_length: int, *, min_length: int = 0) -> StringConstraints:
    return StringConstraints(min_length=min_length, max_length=max_length)


FeatureId = Annotated[str, _id("feature")]
NfrId = Annotated[str, _id("nfr")]
ComponentId = Annotated[str, _id("component")]
ThreatId = Annotated[str, _id("threat")]
TaskId = Annotated[str, _id("task")]
AcceptanceId = Annotated[str, _id("acceptance")]
QuestionId = Annotated[str, _id("question")]
AssumptionId = Annotated[str, _id("assumption")]
AdrId = Annotated[str, _id("adr")]
EventId = Annotated[str, _id("event")]
RunId = Annotated[str, _id("run")]
TraceId = Annotated[
    str,
    StringConstraints(
        pattern=rf"^(?:{ID_PATTERNS['feature']}|{ID_PATTERNS['threat']}|{ID_PATTERNS['nfr']})$"
    ),
]

Sha256 = Annotated[str, StringConstraints(pattern=r"^[0-9a-f]{64}$")]
GitSha = Annotated[str, StringConstraints(pattern=r"^[0-9a-f]{40}(?:[0-9a-f]{24})?$")]
Token = Annotated[str, StringConstraints(pattern=r"^[a-z0-9][a-z0-9.+_\-]{0,39}$")]
"""A short lowercase name: a stack part, a category or a template name."""

Str40 = Annotated[str, _text(40, min_length=1)]
Str120 = Annotated[str, _text(120, min_length=1)]
Str200 = Annotated[str, _text(200)]
Str300 = Annotated[str, _text(300)]
Str500 = Annotated[str, _text(500, min_length=1)]
Str1000 = Annotated[str, _text(1000)]
Str4000 = Annotated[str, _text(4000)]
Body = Annotated[str, StringConstraints(max_length=262_144, strip_whitespace=False)]
"""A Markdown body, kept byte for byte."""

SafeGlob = Annotated[str, AfterValidator(_glob)]
"""A glob that passed `safe_rel_glob`, stored normalized."""
RelPath = Annotated[str, AfterValidator(_relpath)]
"""A relative path with valid syntax, for recorded metadata only."""


class FrontMatter(StrictModel):
    """The YAML front matter every Markdown artifact starts with."""

    schema_version: Literal[1] = 1


class YamlArtifact(StrictModel):
    """A `.pm/` artifact stored as one YAML document."""

    artifact_kind: ClassVar[ArtifactKind]
    schema_version: Literal[1] = 1

    def to_document(self) -> dict[str, object]:
        """The plain data written to the file, in schema order."""
        return self.model_dump(mode="json")


class MarkdownArtifact[M: FrontMatter](StrictModel):
    """A `.pm/` artifact stored as YAML front matter plus a free Markdown body (§6.2)."""

    artifact_kind: ClassVar[ArtifactKind]
    meta: M
    body: Body = ""

    def front_matter(self) -> dict[str, object]:
        """The plain front matter data, in schema order."""
        return self.meta.model_dump(mode="json")
