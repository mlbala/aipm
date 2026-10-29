"""The `.pm/` artifact schemas, v1 (ARCHITECTURE §6.3), plus the repo map written by `init`."""

import re
from enum import StrEnum
from typing import Annotated, ClassVar, Literal, Self

from pydantic import AwareDatetime, Field, StringConstraints, model_validator

from aipm.domain.models.base import (
    ADR_DIR,
    AcceptanceId,
    AdrId,
    ArtifactKind,
    AssumptionId,
    ComponentId,
    FeatureId,
    FrontMatter,
    GitSha,
    MarkdownArtifact,
    NfrId,
    QuestionId,
    RelPath,
    RunId,
    SafeGlob,
    Severity,
    Sha256,
    Str40,
    Str120,
    Str200,
    Str300,
    Str500,
    Str1000,
    Str4000,
    StrictModel,
    TaskId,
    ThreatId,
    Token,
    TraceId,
    YamlArtifact,
)

ProjectName = Annotated[str, StringConstraints(pattern=r"^[a-z0-9][a-z0-9\-]{1,63}$")]
GateName = Annotated[str, StringConstraints(pattern=r"^[a-z][a-z0-9_]{0,31}$")]
Score = Annotated[float, Field(ge=0.0, le=1.0)]


def _unique(ids: list[str], what: str) -> None:
    seen: set[str] = set()
    for item in ids:
        if item in seen:
            raise ValueError(f"duplicate {what} {item}")
        seen.add(item)


# ---------------------------------------------------------------- requirements.yaml


class Mode(StrEnum):
    """Whether the repository already had code when aipm started."""

    GREENFIELD = "greenfield"
    BROWNFIELD = "brownfield"


class Dimension(StrEnum):
    """The coverage checklist (ARCHITECTURE §8.1)."""

    PROBLEM_GOALS = "problem_goals"
    USERS_PERSONAS = "users_personas"
    CORE_FEATURES = "core_features"
    DATA = "data"
    INTEGRATIONS = "integrations"
    SCALE_PERFORMANCE = "scale_performance"
    SECURITY_COMPLIANCE = "security_compliance"
    DEPLOYMENT_OPS = "deployment_ops"
    CONSTRAINTS = "constraints"
    SUCCESS_METRICS = "success_metrics"


class SourceKind(StrEnum):
    """Where discovery input came from."""

    TERMINAL = "terminal"
    FILE = "file"
    ANSWERS = "answers"


class AnswerSource(StrEnum):
    """Who supplied an answer."""

    USER = "user"
    FILE = "file"
    DEFAULT = "default"


class ProjectInfo(StrictModel):
    """The project's name and one-line summary."""

    name: ProjectName
    one_liner: Str200 = ""


class Source(StrictModel):
    """One discovery input. File inputs record their path and hash."""

    kind: SourceKind
    path: RelPath | None = None
    sha256: Sha256 | None = None

    @model_validator(mode="after")
    def _file_fields(self) -> Self:
        has_file = self.path is not None and self.sha256 is not None
        if self.kind is SourceKind.TERMINAL and (self.path or self.sha256):
            raise ValueError("a terminal source has no path or sha256")
        if self.kind is not SourceKind.TERMINAL and not has_file:
            raise ValueError(f"a {self.kind.value} source needs path and sha256")
        return self


class Answer(StrictModel):
    """An answered discovery question."""

    id: QuestionId
    dimension: Dimension
    question: Str500
    answer: Str4000
    source: AnswerSource
    confirmed: bool = False


class Assumption(StrictModel):
    """A written assumption that replaces a skipped question (P-4)."""

    id: AssumptionId
    dimension: Dimension
    statement: Str500
    reason: Str300 = ""
    confirmed: bool = False


class OpenQuestion(StrictModel):
    """A question still waiting for an answer."""

    id: QuestionId
    dimension: Dimension
    question: Str500
    blocking: bool = False


class Coverage(StrictModel):
    """The coverage score and its per-dimension parts (ARCHITECTURE §8.1)."""

    score: Score = 0.0
    rounds: Annotated[int, Field(ge=0, le=50)] = 0
    by_dimension: dict[Dimension, Score] = Field(default_factory=dict[Dimension, float])


class RequirementsDoc(YamlArtifact):
    """`requirements.yaml`: the source of truth for discovery."""

    artifact_kind: ClassVar[ArtifactKind] = ArtifactKind.REQUIREMENTS
    project: ProjectInfo
    mode: Mode
    sources: list[Source] = Field(default_factory=list[Source], max_length=20)
    answers: list[Answer] = Field(default_factory=list[Answer], max_length=300)
    assumptions: list[Assumption] = Field(default_factory=list[Assumption], max_length=100)
    open_questions: list[OpenQuestion] = Field(default_factory=list[OpenQuestion], max_length=100)
    coverage: Coverage = Field(default_factory=Coverage)

    @model_validator(mode="after")
    def _unique_ids(self) -> Self:
        _unique([a.id for a in self.answers] + [q.id for q in self.open_questions], "question")
        _unique([a.id for a in self.assumptions], "assumption")
        return self


# ---------------------------------------------------------------- prd.md


class Priority(StrEnum):
    """MoSCoW priority."""

    MUST = "must"
    SHOULD = "should"
    COULD = "could"
    WONT = "wont"


class PrdDerivedFrom(StrictModel):
    """The requirements hash the PRD was written from."""

    requirements: Sha256


class Feature(StrictModel):
    """A PRD feature."""

    id: FeatureId
    title: Str120
    priority: Priority


class NonFunctional(StrictModel):
    """A non-functional requirement."""

    id: NfrId
    category: Token
    statement: Str500


class PrdFrontMatter(FrontMatter):
    """`prd.md` front matter."""

    kind: Literal["prd"] = "prd"
    derived_from: PrdDerivedFrom
    features: list[Feature] = Field(default_factory=list[Feature], max_length=60)
    non_functional: list[NonFunctional] = Field(default_factory=list[NonFunctional], max_length=40)

    @model_validator(mode="after")
    def _unique_ids(self) -> Self:
        _unique([f.id for f in self.features], "feature")
        _unique([n.id for n in self.non_functional], "requirement")
        return self


class PrdDoc(MarkdownArtifact[PrdFrontMatter]):
    """`prd.md`."""

    artifact_kind: ClassVar[ArtifactKind] = ArtifactKind.PRD


# ---------------------------------------------------------------- architecture.md


class ArchitectureDerivedFrom(StrictModel):
    """The PRD hash the architecture was written from."""

    prd: Sha256


class Stack(StrictModel):
    """The chosen stack, as short lowercase names."""

    language: Token | None = None
    framework: Token | None = None
    database: Token | None = None
    package_manager: Token | None = None
    test_framework: Token | None = None
    deploy: Token | None = None


class Component(StrictModel):
    """An architecture component and the paths it lives in."""

    id: ComponentId
    name: Str40
    paths: list[SafeGlob] = Field(default_factory=list[SafeGlob], max_length=20)
    responsibility: Str300 = ""


class ArchitectureFrontMatter(FrontMatter):
    """`architecture.md` front matter."""

    kind: Literal["architecture"] = "architecture"
    derived_from: ArchitectureDerivedFrom
    stack: Stack = Field(default_factory=Stack)
    stack_template: Token
    components: list[Component] = Field(default_factory=list[Component], max_length=40)
    is_llm_app: bool = False
    decisions: list[AdrId] = Field(default_factory=list[AdrId], max_length=50)

    @model_validator(mode="after")
    def _unique_ids(self) -> Self:
        _unique([c.id for c in self.components], "component")
        return self


class ArchitectureDoc(MarkdownArtifact[ArchitectureFrontMatter]):
    """`architecture.md`."""

    artifact_kind: ClassVar[ArtifactKind] = ArtifactKind.ARCHITECTURE


# ---------------------------------------------------------------- threat-model.md


class Stride(StrEnum):
    """STRIDE category."""

    S = "S"
    T = "T"
    R = "R"
    I = "I"  # noqa: E741 - the STRIDE letter
    D = "D"
    E = "E"


class ThreatModelDerivedFrom(StrictModel):
    """The architecture hash the threat model was written from."""

    architecture: Sha256


class Threat(StrictModel):
    """One threat and its mitigation."""

    id: ThreatId
    stride: Stride
    owasp_llm: Annotated[str, StringConstraints(pattern=r"^LLM(?:0[1-9]|10)$")] | None = None
    component: ComponentId
    title: Str120
    severity: Severity
    mitigation: Str1000


class ThreatModelFrontMatter(FrontMatter):
    """`threat-model.md` front matter."""

    kind: Literal["threat_model"] = "threat_model"
    derived_from: ThreatModelDerivedFrom
    threats: list[Threat] = Field(default_factory=list[Threat], max_length=80)

    @model_validator(mode="after")
    def _unique_ids(self) -> Self:
        _unique([t.id for t in self.threats], "threat")
        return self


class ThreatModelDoc(MarkdownArtifact[ThreatModelFrontMatter]):
    """`threat-model.md`."""

    artifact_kind: ClassVar[ArtifactKind] = ArtifactKind.THREAT_MODEL


# ---------------------------------------------------------------- adr/NNNN-<slug>.md

_ADR_FILE = re.compile(r"[0-9]{4}-[a-z0-9]+(?:-[a-z0-9]+)*\.md")
_SLUG_MAX = 48


class AdrFrontMatter(FrontMatter):
    """An ADR's front matter. aipm allocates the ID; the title is model text (T2 until G2)."""

    kind: Literal["adr"] = "adr"
    id: AdrId
    title: Str120
    status: Literal["accepted"] = "accepted"


class AdrDoc(MarkdownArtifact[AdrFrontMatter]):
    """One architecture decision record in `.pm/adr/`."""

    artifact_kind: ClassVar[ArtifactKind] = ArtifactKind.ADR

    @property
    def file_name(self) -> str:
        """`NNNN-<slug>.md`, built by aipm from the ID and a lowercase reduction of the title."""
        return adr_file_name(self.meta.id, self.meta.title)


def adr_file_name(adr_id: str, title: str) -> str:
    """The file name for an ADR: digits from the ID, then `[a-z0-9-]` from the title."""
    number = adr_id.removeprefix("ADR-")
    words = re.findall(r"[a-z0-9]+", title.casefold())
    slug = "-".join(words)[:_SLUG_MAX].strip("-") or "decision"
    name = f"{number}-{slug}.md"
    if not is_adr_file_name(name):
        raise ValueError(f"not an ADR file name: {name!r}")
    return name


def is_adr_file_name(name: str) -> bool:
    """Whether `name` is a file name aipm would write in `.pm/adr/`."""
    return len(name) <= 64 and _ADR_FILE.fullmatch(name) is not None


# ---------------------------------------------------------------- tasks.yaml


class TaskType(StrEnum):
    """What kind of work a task is."""

    FEATURE = "feature"
    TEST = "test"
    INFRA = "infra"
    DOCS = "docs"
    REFACTOR = "refactor"
    SECURITY = "security"


class TaskSize(StrEnum):
    """Rough task size; L must be split unless justified."""

    S = "S"
    M = "M"
    L = "L"


class TaskStatus(StrEnum):
    """Task state."""

    TODO = "todo"
    IN_PROGRESS = "in_progress"
    BLOCKED = "blocked"
    DONE = "done"
    SKIPPED = "skipped"


class Ecosystem(StrEnum):
    """Package ecosystems a task may add dependencies from."""

    PYPI = "pypi"
    NPM = "npm"


class BlockedReason(StrEnum):
    """Why a task is blocked."""

    AGENT_BLOCKED = "agent_blocked"
    GATES_FAILED = "gates_failed"
    MERGE_CONFLICT = "merge_conflict"
    POLICY_VIOLATION = "policy_violation"
    BUDGET_EXCEEDED = "budget_exceeded"
    TIMEOUT = "timeout"
    INTERRUPTED = "interrupted"
    MANUAL = "manual"


_PACKAGE_NAMES = {
    Ecosystem.PYPI: r"^[A-Za-z0-9](?:[A-Za-z0-9._\-]{0,98}[A-Za-z0-9])?$",
    Ecosystem.NPM: r"^(?:@[a-z0-9\-~][a-z0-9\-._~]{0,99}/)?[a-z0-9\-~][a-z0-9\-._~]{0,113}$",
}


class DependencyAdd(StrictModel):
    """A new dependency the task declares (checked later by the deps gate)."""

    ecosystem: Ecosystem
    name: Annotated[str, StringConstraints(min_length=1, max_length=214)]

    @model_validator(mode="after")
    def _name_format(self) -> Self:
        if not re.fullmatch(_PACKAGE_NAMES[self.ecosystem], self.name):
            raise ValueError(f"not a valid {self.ecosystem.value} package name")
        return self


class AcceptanceCriterion(StrictModel):
    """One acceptance criterion; tests carry its ID."""

    id: AcceptanceId
    text: Str500


class Blocked(StrictModel):
    """Why a task stopped, and the question for the human, if any."""

    reason: BlockedReason
    detail: Str1000 = ""
    question: Str300 | None = None


class Done(StrictModel):
    """Where a finished task landed."""

    commit: GitSha
    run_id: RunId | None = None
    at: AwareDatetime


class Task(StrictModel):
    """One task in the DAG (ARCHITECTURE §6.3)."""

    id: TaskId
    title: Str120
    description: Str4000 = ""
    type: TaskType
    traces: list[TraceId] = Field(default_factory=list[TraceId], max_length=20)
    depends_on: list[TaskId] = Field(default_factory=list[TaskId], max_length=20)
    owns_files: list[SafeGlob] = Field(default_factory=list[SafeGlob], max_length=40)
    reads_files: list[SafeGlob] = Field(default_factory=list[SafeGlob], max_length=40)
    deps_add: list[DependencyAdd] = Field(default_factory=list[DependencyAdd], max_length=20)
    acceptance: list[AcceptanceCriterion] = Field(min_length=1, max_length=10)
    gates: list[GateName] = Field(default_factory=list[GateName], max_length=12)
    size: TaskSize
    status: TaskStatus = TaskStatus.TODO
    attempts: Annotated[int, Field(ge=0, le=100)] = 0
    base_sha: GitSha | None = None
    blocked: Blocked | None = None
    done: Done | None = None

    @model_validator(mode="after")
    def _consistent(self) -> Self:
        number = self.id.removeprefix("T-")
        for criterion in self.acceptance:
            if not criterion.id.startswith(f"AC-T{number}-"):
                raise ValueError(f"{criterion.id} does not belong to {self.id}")
        _unique([c.id for c in self.acceptance], "acceptance criterion")
        if self.id in self.depends_on:
            raise ValueError(f"{self.id} depends on itself")
        if (self.status is TaskStatus.BLOCKED) != (self.blocked is not None):
            raise ValueError("'blocked' is set exactly when status is blocked")
        if (self.status is TaskStatus.DONE) != (self.done is not None):
            raise ValueError("'done' is set exactly when status is done")
        return self


class TasksDerivedFrom(StrictModel):
    """The upstream hashes the plan was made from."""

    prd: Sha256
    architecture: Sha256
    threat_model: Sha256


class TasksDoc(YamlArtifact):
    """`tasks.yaml`: the task DAG."""

    artifact_kind: ClassVar[ArtifactKind] = ArtifactKind.TASKS
    derived_from: TasksDerivedFrom
    tasks: list[Task] = Field(default_factory=list[Task], max_length=200)

    @model_validator(mode="after")
    def _unique_ids(self) -> Self:
        _unique([t.id for t in self.tasks], "task")
        return self


# ---------------------------------------------------------------- approvals.yaml


class ApprovalGate(StrEnum):
    """Human approval points (ARCHITECTURE §7.2)."""

    G1 = "G1"
    G2 = "G2"
    G3 = "G3"
    CONTEXT = "context"


class Approval(StrictModel):
    """One recorded approval: a team record, never a security control (SECURITY.md §6)."""

    gate: ApprovalGate
    artifact: RelPath
    sha256: Sha256
    by: Str200
    at: AwareDatetime


class OverrideReason(StrEnum):
    """Why a command ran on input that is not approved and current."""

    STALE = "stale"
    UNAPPROVED = "unapproved"


class StaleOverride(StrictModel):
    """A recorded `--accept-stale` run (ARCHITECTURE §7.1). Never counts as an approval."""

    command: Literal["design", "plan"]
    artifact: RelPath
    sha256: Sha256
    reason: OverrideReason
    by: Str200
    at: AwareDatetime


APPROVED_NAMES = {
    ArtifactKind.PRD: "prd.md",
    ArtifactKind.ARCHITECTURE: "architecture.md",
    ArtifactKind.THREAT_MODEL: "threat-model.md",
    ArtifactKind.ADR: ADR_DIR,
    ArtifactKind.TASKS: "tasks.yaml",
}
"""The `artifact` value an approval records for each kind (G2 approves `adr` as a whole)."""


class ApprovalsDoc(YamlArtifact):
    """`approvals.yaml`."""

    artifact_kind: ClassVar[ArtifactKind] = ArtifactKind.APPROVALS
    approvals: list[Approval] = Field(default_factory=list[Approval], max_length=1000)
    overrides: list[StaleOverride] = Field(default_factory=list[StaleOverride], max_length=1000)

    def has(self, gate: ApprovalGate, artifact: str, sha256: str | None) -> bool:
        """Whether this exact hash of the artifact has an approval for the gate."""
        if not sha256:
            return False
        return any(
            a.gate is gate and a.artifact == artifact and a.sha256 == sha256 for a in self.approvals
        )

    def to_document(self) -> dict[str, object]:
        """`overrides` is written only once there is one, so older files keep their bytes."""
        data = super().to_document()
        if not self.overrides:
            data.pop("overrides", None)
        return data


# ---------------------------------------------------------------- repo-map.md


class RepoMapFrontMatter(FrontMatter):
    """`repo-map.md` front matter. No timestamps, so an unchanged repo maps to the same bytes."""

    kind: Literal["repo_map"] = "repo_map"
    mode: Mode
    stack_template: Token | None = None
    entries: Annotated[int, Field(ge=0, le=300)] = 0
    truncated: bool = False
    manifests: list[RelPath] = Field(default_factory=list[RelPath], max_length=20)


class RepoMapDoc(MarkdownArtifact[RepoMapFrontMatter]):
    """`repo-map.md`: a sanitized summary of the existing repository (T2 when read back)."""

    artifact_kind: ClassVar[ArtifactKind] = ArtifactKind.REPO_MAP
