"""The configuration schema (ARCHITECTURE §15) and its key classes.

Every leaf field carries its key class as `Annotated` metadata: `KeyClass.USER_ONLY`, or a
`Tighten` rule (which makes it tighten-only and says which value is stricter). A field with
neither is repo-ok. The loader reads these markers; nothing else decides what a repo may set.
"""

from collections.abc import Callable
from dataclasses import dataclass
from enum import StrEnum
from typing import Annotated, Any, ClassVar, Literal

from pydantic import AfterValidator, Field, StringConstraints, field_validator

from aipm.domain.errors import AipmError
from aipm.domain.models import (
    ApprovalGate,
    ArtifactKind,
    GateDef,
    NetworkProfile,
    PrepareDef,
    RoleName,
    StrictModel,
    ToolName,
    YamlArtifact,
)
from aipm.domain.models.artifacts import GateName, ProjectName
from aipm.domain.models.base import Token
from aipm.domain.models.gates import ArgvList
from aipm.security.command_policy import CommandPolicy
from aipm.security.paths import normalize_glob, normalize_relpath
from aipm.security.redact import Redactor


class KeyClass(StrEnum):
    """How a repo-level value is treated (ARCHITECTURE §15, SECURITY.md §6 rule 5)."""

    USER_ONLY = "user-only"
    TIGHTEN_ONLY = "tighten-only"
    REPO_OK = "repo-ok"


@dataclass(frozen=True, slots=True)
class Tighten:
    """A tighten-only key and how to pick the stricter of two values.

    `rule` is `true-wins`, `min`, `max`, `min-duration`, `union`, `intersection`, or `rank`
    (with `order` listing the values strictest first).
    """

    rule: Literal["true-wins", "min", "max", "min-duration", "union", "intersection", "rank"]
    order: tuple[str, ...] = ()


USER_ONLY = KeyClass.USER_ONLY
TRUE_WINS = Tighten("true-wins")
MIN = Tighten("min")
MAX = Tighten("max")
MIN_DURATION = Tighten("min-duration")
UNION = Tighten("union")
INTERSECTION = Tighten("intersection")
NETWORK_RANK = Tighten("rank", ("none", "api-only", "registries"))


def _as_value_error[T](check: Callable[[Any], T], value: object) -> T:
    """Run an aipm check inside a pydantic validator, turning its error into a ValueError."""
    try:
        return check(value)
    except AipmError as exc:
        raise ValueError(exc.message) from None


def _glob_syntax(value: str) -> str:
    return _as_value_error(normalize_glob, value)


def _relpath_syntax(value: str) -> str:
    return _as_value_error(normalize_relpath, value)


def _branch_name(value: str) -> str:
    if ".." in value or "//" in value or value.endswith(("/", ".lock")):
        raise ValueError("not a safe branch name")
    return value


def _duration_seconds(value: str) -> int:
    number, unit = int(value[:-1]), value[-1]
    return number * {"s": 1, "m": 60, "h": 3600}[unit]


EnvName = Annotated[str, StringConstraints(pattern=r"^[A-Za-z_][A-Za-z0-9_]{0,99}$")]
ModelName = Annotated[str, StringConstraints(pattern=r"^[A-Za-z0-9][A-Za-z0-9._:/\-]{0,99}$")]
Duration = Annotated[str, StringConstraints(pattern=r"^[1-9]\d{0,4}[smh]$")]
GlobPattern = Annotated[str, AfterValidator(_glob_syntax)]
RelPathSyntax = Annotated[str, AfterValidator(_relpath_syntax)]
Domain = Annotated[
    str,
    StringConstraints(
        max_length=253,
        pattern=r"^[a-z0-9](?:[a-z0-9\-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9\-]{0,61}[a-z0-9])?)+$",
        to_lower=True,
    ),
]
BaseUrl = Annotated[str, StringConstraints(pattern=r"^https?://[^\s]{1,300}$")]
ArgvPrefixes = Annotated[list[ArgvList], Field(max_length=32)]
RulePack = Annotated[str, StringConstraints(pattern=r"^(?:p|r)/[a-z0-9][a-z0-9.\-]{0,79}$")]


class Provider(StrEnum):
    """LLM providers (ARCHITECTURE §14)."""

    ANTHROPIC = "anthropic"
    OPENAI_COMPATIBLE = "openai-compatible"


class SandboxMode(StrEnum):
    """`dispatch.sandbox`."""

    AUTO = "auto"
    SRT = "srt"
    TOOL_NATIVE = "tool-native"
    NONE = "none"


class NewDependencies(StrEnum):
    """`security.allow_new_dependencies`."""

    ASK = "ask"
    ALLOW = "allow"
    DENY = "deny"


class Price(StrictModel):
    """USD per million tokens for one model."""

    input_per_mtok: Annotated[float, Field(ge=0, le=10_000)]
    output_per_mtok: Annotated[float, Field(ge=0, le=10_000)]


_MODEL_KEYS = frozenset({"default", *(role.value for role in RoleName)})


class ProjectConfig(StrictModel):
    """`project`."""

    name: ProjectName | None = None


class LlmConfig(StrictModel):
    """`llm`. The gateway never sends sampling parameters, so there are no keys for them."""

    provider: Annotated[Provider, USER_ONLY] = Provider.ANTHROPIC
    base_url: Annotated[BaseUrl | None, USER_ONLY] = None
    api_key_env: Annotated[EnvName, USER_ONLY] = "ANTHROPIC_API_KEY"
    models: dict[str, ModelName] = Field(
        default_factory=lambda: {
            "default": "claude-sonnet-5-5",
            "interviewer": "claude-haiku-5-5",
            "ac_reviewer": "claude-haiku-5-5",
        }
    )
    max_output_tokens: Annotated[int, Field(ge=1, le=64_000)] = 8000
    pricing: Annotated[dict[ModelName, Price], USER_ONLY] = Field(
        default_factory=dict[str, Price], max_length=50
    )

    @field_validator("models")
    @classmethod
    def _model_keys(cls, value: dict[str, str]) -> dict[str, str]:
        unknown = sorted(set(value) - _MODEL_KEYS)
        if unknown:
            raise ValueError(f"unknown llm.models keys: {', '.join(unknown)}")
        return value


class DiscoverConfig(StrictModel):
    """`discover`."""

    coverage_threshold: Annotated[float, Field(ge=0.0, le=1.0)] = 0.85
    max_rounds: Annotated[int, Field(ge=1, le=20)] = 6
    questions_per_round: Annotated[int, Field(ge=3, le=5)] = 4


class ApprovalsConfig(StrictModel):
    """`approvals`."""

    gates: list[ApprovalGate] = Field(
        default_factory=lambda: [ApprovalGate.G1, ApprovalGate.G2, ApprovalGate.G3],
        max_length=4,
    )


class PlanConfig(StrictModel):
    """`plan`."""

    serialized_paths: list[GlobPattern] = Field(
        default_factory=lambda: [
            "pyproject.toml",
            "uv.lock",
            "package.json",
            "*lock*",
            "migrations/**",
        ],
        max_length=50,
    )


class ToolConfig(StrictModel):
    """`dispatch.tools.<tool>`."""

    bare: Annotated[bool, TRUE_WINS] = True
    pass_env: Annotated[list[EnvName], USER_ONLY] = Field(default_factory=list[str], max_length=20)
    allow_auto_mode: Annotated[bool, USER_ONLY] = False


class DispatchConfig(StrictModel):
    """`dispatch`."""

    enabled: bool = True
    default_tool: ToolName = ToolName.CLAUDE
    parallel: Annotated[int, Field(ge=1, le=8), MIN] = 1
    max_retries: Annotated[int, Field(ge=0, le=10), MIN] = 3
    task_timeout: Annotated[Duration, MIN_DURATION] = "20m"
    fail_fast: bool = True
    sandbox: Annotated[SandboxMode, Tighten("rank", ("srt", "tool-native", "auto", "none"))] = (
        SandboxMode.AUTO
    )
    tools: dict[ToolName, ToolConfig] = Field(
        default_factory=lambda: {ToolName.CLAUDE: ToolConfig()}
    )


class BudgetConfig(StrictModel):
    """`budget`: the minimum wins."""

    run_usd: Annotated[float, Field(ge=0, le=100_000), MIN] = 10.0
    task_usd: Annotated[float, Field(ge=0, le=100_000), MIN] = 2.0
    run_tokens: Annotated[int, Field(ge=0, le=1_000_000_000), MIN] = 2_000_000


class SemgrepConfig(StrictModel):
    """`scanners.semgrep`: pinned rule packs; `--config auto` is never used."""

    configs: list[
        Annotated[str, StringConstraints(pattern=r"^(?:p|r)/[a-z0-9][a-z0-9.\-]{0,79}$")]
    ] = Field(default_factory=lambda: ["p/python", "p/secrets"], max_length=20)


class ScannerDef(StrictModel):
    """A config-defined scanner (v0.2); part of the execution surface."""

    run: ArgvList


class ScannersConfig(StrictModel):
    """`scanners` (v0.2)."""

    semgrep: SemgrepConfig = Field(default_factory=SemgrepConfig)
    extra: dict[GateName, ScannerDef] = Field(default_factory=dict[str, ScannerDef], max_length=10)


class NetworkConfig(StrictModel):
    """`security.network`: the network profile for each kind of process."""

    agent: Annotated[NetworkProfile, NETWORK_RANK] = NetworkProfile.API_ONLY
    gates: Annotated[NetworkProfile, NETWORK_RANK] = NetworkProfile.NONE
    prepare: Annotated[NetworkProfile, NETWORK_RANK] = NetworkProfile.REGISTRIES


class SecurityConfig(StrictModel):
    """`security`: tighten-only, except `extra_allowed_executables`, which is user-only."""

    require_sandbox: Annotated[bool, TRUE_WINS] = False
    network: NetworkConfig = Field(default_factory=NetworkConfig)
    allow_new_dependencies: Annotated[
        NewDependencies, Tighten("rank", ("deny", "ask", "allow"))
    ] = NewDependencies.ASK
    min_dependency_age_days: Annotated[int, Field(ge=0, le=3650), MAX] = 30
    extra_protected_paths: Annotated[list[GlobPattern], UNION] = Field(
        default_factory=list[str], max_length=50
    )
    extra_redact_patterns: Annotated[
        list[Annotated[str, StringConstraints(min_length=1, max_length=200)]], UNION
    ] = Field(default_factory=list[str], max_length=20)
    extra_allowed_executables: Annotated[ArgvPrefixes, USER_ONLY] = Field(
        default_factory=list[tuple[str, ...]]
    )
    max_input_kib: Annotated[int, Field(ge=1, le=10_240), MIN] = 256

    @field_validator("extra_redact_patterns")
    @classmethod
    def _patterns_compile(cls, value: list[str]) -> list[str]:
        _as_value_error(lambda patterns: Redactor({}, extra_patterns=patterns), value)
        return value


class ContextConfig(StrictModel):
    """`context`."""

    allowed_url_domains: Annotated[list[Domain], INTERSECTION] = Field(
        default_factory=list[str], max_length=50
    )


class GitConfig(StrictModel):
    """`git`."""

    integration_branch: Annotated[
        str,
        StringConstraints(pattern=r"^[A-Za-z0-9][A-Za-z0-9._/\-]{0,99}$"),
        AfterValidator(_branch_name),
    ] = "aipm/integration"


class LoggingConfig(StrictModel):
    """`logging`."""

    level: Literal["debug", "info", "warning", "error"] = "info"
    json_lines: Annotated[bool, Field(alias="json")] = False


class Config(YamlArtifact):
    """The merged, validated configuration; also the shape of `.pm/config.yaml`."""

    artifact_kind: ClassVar[ArtifactKind] = ArtifactKind.CONFIG
    project: ProjectConfig = Field(default_factory=ProjectConfig)
    stack_template: Token | None = None
    llm: LlmConfig = Field(default_factory=LlmConfig)
    discover: DiscoverConfig = Field(default_factory=DiscoverConfig)
    approvals: ApprovalsConfig = Field(default_factory=ApprovalsConfig)
    plan: PlanConfig = Field(default_factory=PlanConfig)
    dispatch: DispatchConfig = Field(default_factory=DispatchConfig)
    budget: BudgetConfig = Field(default_factory=BudgetConfig)
    allowed_executables: ArgvPrefixes = Field(default_factory=list[tuple[str, ...]])
    test_roots: list[RelPathSyntax] = Field(default_factory=list[str], max_length=10)
    prepare: PrepareDef | None = None
    gates: dict[GateName, GateDef] = Field(default_factory=dict[str, GateDef], max_length=20)
    scanners: ScannersConfig = Field(default_factory=ScannersConfig)
    security: SecurityConfig = Field(default_factory=SecurityConfig)
    context: ContextConfig = Field(default_factory=ContextConfig)
    git: GitConfig = Field(default_factory=GitConfig)
    logging: LoggingConfig = Field(default_factory=LoggingConfig)

    def to_document(self) -> dict[str, object]:
        """Only the keys that were set, so a repo file never restates defaults or user keys."""
        data = self.model_dump(mode="json", exclude_unset=True, by_alias=True)
        data.pop("schema_version", None)
        return {"schema_version": self.schema_version, **data}

    def command_policy(self) -> CommandPolicy:
        """The command policy: the stack's prefixes plus the user-level extras (SECURITY.md §10)."""
        prefixes = tuple(self.allowed_executables) + tuple(self.security.extra_allowed_executables)
        return CommandPolicy(
            allowed_prefixes=prefixes,
            test_roots=tuple(self.test_roots),
            extra_protected=tuple(self.security.extra_protected_paths),
        )


def key_class(metadata: list[Any]) -> KeyClass | Tighten:
    """The key class recorded in a field's metadata (`REPO_OK` when there is none)."""
    for item in metadata:
        if isinstance(item, (KeyClass, Tighten)):
            return item
    return KeyClass.REPO_OK


_COMBINE: dict[str, Callable[[Tighten, Any, Any], Any]] = {
    "true-wins": lambda _, a, b: bool(a) or bool(b),
    "min": lambda _, a, b: min(a, b),
    "max": lambda _, a, b: max(a, b),
    "min-duration": lambda _, a, b: min(a, b, key=_duration_seconds),
    "union": lambda _, a, b: [*a, *(item for item in b if item not in a)],
    "intersection": lambda _, a, b: [item for item in a if item in b],
    "rank": lambda rule, a, b: min(a, b, key=lambda value: rule.order.index(str(value))),
}


def stricter(rule: Tighten, current: Any, proposed: Any) -> Any:
    """Return the stricter combination of the current and proposed values."""
    return _COMBINE[rule.rule](rule, current, proposed)
