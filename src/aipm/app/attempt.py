"""What one attempt shares between `aipm verify` (manual mode) and the build loop (§12.4, §12.7).

- The attempt snapshot a task starts from and the check policy built from config (ADR-0021):
  `aipm prompt` takes the snapshot when a task starts; `aipm verify` compares the tree with it;
  `aipm task reset` removes it.
- The pieces around the post-change checks and the gates: the checks as a report entry, why the
  prepare step must not run, the AC reviewer, the hashes that tell whether a gate changed a file
  the checks read, the base commit's ignore lines, and the security events for severe
  violations.
"""

import secrets
import shutil
import tempfile
from collections.abc import Sequence
from datetime import UTC, datetime
from pathlib import Path

from aipm.app import runtime
from aipm.config.schema import Config
from aipm.domain.errors import AipmError, PolicyViolation
from aipm.domain.models import (
    BuiltinGate,
    ChangeSet,
    ChangeStatus,
    GateFinding,
    GateResult,
    GateStatus,
    RoleName,
    SecurityEventKind,
    Severity,
    Task,
)
from aipm.execution import git
from aipm.execution.git import (
    MAX_CONTENT_BYTES,
    ChangeInputs,
    change_set,
    integrity_snapshot,
    snapshot_files,
)
from aipm.gates.builtin.ac_review import Reviewer
from aipm.llm.gateway import TokenBudget, open_gateway
from aipm.roles import ac_reviewer
from aipm.roles.ac_reviewer import ACReview, ACReviewInput
from aipm.security.budget import TokenCounter
from aipm.security.diff_checks import (
    CheckPolicy,
    Kind,
    Level,
    Violation,
    content_limit,
    is_dependency_path,
    is_watched,
    needs_content,
    severe,
)
from aipm.security.paths import is_within
from aipm.state.attempts import AttemptSnapshot, WriteLedger, new_snapshot, save_snapshot
from aipm.state.store import FileStateStore

MAX_EVENTS = 20
CHECKS = "checks"


def check_policy(cfg: Config) -> CheckPolicy:
    """The post-change check settings from the merged config."""
    return CheckPolicy(
        test_roots=tuple(cfg.test_roots) or ("tests",),
        extra_protected=tuple(cfg.security.extra_protected_paths),
        allow_new_dependencies=cfg.security.allow_new_dependencies.value,
    )


def take_snapshot(root: Path, task_id: str, base_sha: str, cfg: Config) -> AttemptSnapshot:
    """Hash what the task starts from and save it outside the repository."""
    policy = check_policy(cfg)
    snapshot = new_snapshot(
        root,
        task_id,
        base_sha,
        integrity=integrity_snapshot(root, Path.home()),
        files=snapshot_files(root, base_sha, watch_ignored=lambda p: is_watched(p, policy)),
    )
    save_snapshot(root, snapshot)
    return snapshot


def changes_since(root: Path, snapshot: AttemptSnapshot, base_sha: str, cfg: Config) -> ChangeSet:
    """What changed since the snapshot (integrity first, before git runs)."""
    policy = check_policy(cfg)
    inputs = ChangeInputs(
        base_sha=base_sha,
        integrity=snapshot.integrity,
        files=snapshot.files,
        ledger=WriteLedger(root).load(),
        extra_protected=policy.extra_protected,
    )
    return change_set(
        root,
        inputs,
        home=Path.home(),
        watch_ignored=lambda p: is_watched(p, policy),
        wants_content=lambda p: needs_content(p, policy.test_roots),
        content_limit=lambda p: content_limit(p, MAX_CONTENT_BYTES),
    )


def new_run_id() -> str:
    """`r-YYYYMMDD-HHMM-xxxx`."""
    return f"r-{datetime.now(UTC):%Y%m%d-%H%M}-{secrets.token_hex(2)}"


def attempt_dir(root: Path, prefix: str = "aipm-verify-") -> Path:
    """A private (0700) temp dir for this attempt, outside the repository."""
    path = Path(tempfile.mkdtemp(prefix=prefix))
    if is_within(path, root):
        shutil.rmtree(path, ignore_errors=True)
        raise PolicyViolation(
            "the temporary directory is inside the repository",
            hint="Check TMPDIR, which a repository .env loaded by a tool such as pipenv can set.",
        )
    return path


def checks_result(violations: Sequence[Violation]) -> GateResult:
    """The post-change checks as a report entry, so a fix prompt sends them as feedback."""
    findings = [
        GateFinding(
            tool="checks",
            rule=v.kind.value,
            path=v.path[:512],
            message=v.detail[:500],
            severity=Severity.CRITICAL if v.level is Level.SEVERE else Severity.MEDIUM,
        )
        for v in violations[:100]
    ]
    worst = "severe" if severe(violations) else "minor"
    summary = f"{len(violations)} {worst} post-change violation(s)" if violations else "clean"
    lines = (f"{v.level.value}: {v.kind.value}: {v.path}: {v.detail}" for v in violations)
    return GateResult(
        name=CHECKS,
        status=GateStatus.FAIL if violations else GateStatus.PASS,
        required=True,
        summary=summary,
        findings=findings,
        output="\n".join(lines)[:65_536],
    )


def reviewer(
    cfg: Config, store: FileStateStore, *, no_cache: bool, tokens: TokenCounter | None = None
) -> tuple[Reviewer | None, str]:
    """The AC reviewer through the LLM gateway, or why it cannot run.

    `tokens` is the run's shared token counter (`budget.run_tokens`, the build loop); without
    it each review may use the whole budget, as one `verify` does.
    """
    if not any(g.builtin is BuiltinGate.AC_REVIEW for g in cfg.gates.values()):
        return None, "the gate menu has no ac_review gate"
    try:
        gateway = open_gateway(
            cfg.llm, redactor=store.redactor, cache=None if no_cache else runtime.llm_cache(store)
        )
    except AipmError as exc:
        return None, f"the AC reviewer cannot run: {exc.message}"
    role = ac_reviewer.create()

    def review(inp: ACReviewInput) -> ACReview:
        limit = cfg.budget.run_tokens if tokens is None else tokens.remaining()
        result = gateway.run(
            RoleName.AC_REVIEWER,
            role.render(inp),
            ACReview,
            budget=TokenBudget(limit),
            template_version=role.template_version,
        )
        if tokens is not None:
            tokens.add(result.input_tokens + result.output_tokens)
        return role.postprocess(result.value, inp)

    return review, ""


def changed_hashes(root: Path, changes: ChangeSet) -> dict[str, str | None]:
    """The task's changed files as the gates are about to see them: what is scanned and linted
    must be what is saved and committed (step 06 security review)."""
    return {
        c.path: git.hash_path(root / c.path)
        for c in changes.files
        if c.status is not ChangeStatus.DELETED and not c.path.startswith(".pm/")
    }


def base_ignores(root: Path, base: str) -> list[str]:
    """The `.gitignore` and `.aipmignore` lines of the base commit."""
    lines: list[str] = []
    for name in (".gitignore", ".aipmignore"):
        data = git.file_at(root, base, name, max_bytes=262_144) or b""
        lines += data.decode("utf-8", errors="replace").splitlines()
    return lines


def moved_since(root: Path, scanned: dict[str, str | None]) -> list[str]:
    """The changed files whose contents differ from what the checks read."""
    return [path for path, digest in scanned.items() if git.hash_path(root / path) != digest]


def prepare_hold(violations: Sequence[Violation]) -> str | None:
    """Why the prepare step must not run: it would install a dependency the checks refused."""
    for v in violations:
        if v.kind is Kind.DEPENDENCY or is_dependency_path(v.path):
            return f"the post-change checks refused a dependency change in {v.path}"
    return None


def record_violations(
    store: FileStateStore, task: Task, violations: Sequence[Violation], *, source: str
) -> None:
    """A security event for each severe violation (SECURITY.md §7.9), at most `MAX_EVENTS`."""
    for violation in severe(violations)[:MAX_EVENTS]:
        store.append_event(
            SecurityEventKind.POST_CHANGE_VIOLATION,
            source=f"{source}:{task.id}",
            detail=f"{violation.kind.value}: {violation.path}: {violation.detail}",
            data={"kind": violation.kind.value, "path": violation.path[:512]},
        )
