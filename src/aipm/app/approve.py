"""`aipm approve`: record a human approval of an artifact (G1-G3, context; ARCHITECTURE §7.2).

`approvals.yaml` is a team record of what was approved, pinned to sha256, never a security
control (SECURITY.md §6): nothing here reads or writes the trust store, and `--yes` only skips the
review prompt. G1 (the PRD) arrives with build prompt 03; design, plan and context follow in
prompts 04 and 05.

An approval pins the exact bytes the user reviewed: the CLI passes the hash it showed, and the
approval is refused if the file changed in between, if the PRD is stale (written from an older
`requirements.yaml`), or while blocking open questions remain.
"""

import getpass
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path

from aipm.app import runtime
from aipm.app.workspace import find_repo_root, require_initialized
from aipm.domain.errors import NotImplementedYet, UsageError
from aipm.domain.models import (
    Approval,
    ApprovalGate,
    ApprovalsDoc,
    ArtifactKind,
    PrdDoc,
    RequirementsDoc,
)
from aipm.security.sanitize import sanitize_text
from aipm.state.layout import artifact_name
from aipm.state.store import FileStateStore, open_store

PRD_FILE = artifact_name(ArtifactKind.PRD)
_LATER = {"design": "04", "plan": "04", "context": "05"}


def approver() -> str:
    """Who approves: the local login name (a record, not an identity check)."""
    try:
        name = getpass.getuser()
    except Exception:  # getuser raises OSError or KeyError without a login name
        name = ""
    clean = " ".join(sanitize_text(name, source="login").text.split())[:200]
    return clean or "unknown"


def load_approvals(store: FileStateStore) -> ApprovalsDoc:
    """`approvals.yaml`, or an empty record."""
    if not store.exists(ArtifactKind.APPROVALS):
        return ApprovalsDoc()
    doc = store.load(ArtifactKind.APPROVALS)
    if not isinstance(doc, ApprovalsDoc):  # pragma: no cover - the store's mapping
        raise UsageError("approvals.yaml did not load as approvals")
    return doc


def is_approved(doc: ApprovalsDoc, gate: ApprovalGate, artifact: str, sha256: str) -> bool:
    """Whether this exact hash of the artifact has an approval for the gate."""
    return any(
        a.gate is gate and a.artifact == artifact and a.sha256 == sha256 for a in doc.approvals
    )


def record_approval(store: FileStateStore, gate: ApprovalGate, artifact: str, sha256: str) -> bool:
    """Append an approval; False if this hash was already approved. The caller holds the lock."""
    doc = load_approvals(store)
    if is_approved(doc, gate, artifact, sha256):
        return False
    entry = Approval(
        gate=gate, artifact=artifact, sha256=sha256, by=approver(), at=datetime.now(UTC)
    )
    store.save(doc.model_copy(update={"approvals": [*doc.approvals, entry]}))
    return True


@dataclass(frozen=True, slots=True)
class PrdReview:
    """What G1 shows, and whatever stops the approval."""

    repo_root: str
    sha256: str
    one_liner: str
    features: tuple[str, ...]
    non_functional: tuple[str, ...]
    assumptions: tuple[str, ...]
    open_questions: tuple[str, ...]
    blocking: tuple[str, ...]
    stale: bool
    approved: bool

    def to_data(self) -> dict[str, object]:
        """The `--json` payload."""
        return {
            "repo": self.repo_root,
            "artifact": PRD_FILE,
            "sha256": self.sha256,
            "features": list(self.features),
            "blocking": list(self.blocking),
            "stale": self.stale,
            "approved": self.approved,
        }


def _store(project: Path | None) -> FileStateStore:
    root = find_repo_root(project)
    require_initialized(root)
    return open_store(root, redactor=runtime.user_redactor())


def _review(store: FileStateStore) -> PrdReview:
    if not store.exists(ArtifactKind.PRD):
        raise UsageError("there is no PRD to approve", hint="Run `aipm discover` first.")
    if not store.exists(ArtifactKind.REQUIREMENTS):
        raise UsageError("prd.md has no requirements.yaml", hint="Run `aipm discover`.")
    prd = store.load(ArtifactKind.PRD)
    requirements = store.load(ArtifactKind.REQUIREMENTS)
    sha = store.sha256(ArtifactKind.PRD)
    req_sha = store.sha256(ArtifactKind.REQUIREMENTS)
    if not isinstance(prd, PrdDoc) or not isinstance(requirements, RequirementsDoc) or not sha:
        raise UsageError("prd.md or requirements.yaml did not load")  # pragma: no cover
    return PrdReview(
        repo_root=str(store.repo_root),
        sha256=sha,
        one_liner=requirements.project.one_liner,
        features=tuple(f"{f.id} ({f.priority.value}): {f.title}" for f in prd.meta.features),
        non_functional=tuple(
            f"{n.id} ({n.category}): {n.statement}" for n in prd.meta.non_functional
        ),
        assumptions=tuple(f"{a.id}: {a.statement}" for a in requirements.assumptions),
        open_questions=tuple(
            f"{q.id}{' (blocking)' if q.blocking else ''}: {q.question}"
            for q in requirements.open_questions
        ),
        blocking=tuple(q.id for q in requirements.open_questions if q.blocking),
        stale=prd.meta.derived_from.requirements != req_sha,
        approved=is_approved(load_approvals(store), ApprovalGate.G1, PRD_FILE, sha),
    )


def check_target(artifact: str) -> None:
    """Only the PRD can be approved before build prompts 04 and 05."""
    if artifact in _LATER:
        raise NotImplementedYet(
            f"approving {artifact} is not implemented yet (build prompt {_LATER[artifact]})",
            hint="See docs/prompts/README.md for the build plan.",
        )
    if artifact != "prd":
        raise UsageError(f"cannot approve {artifact!r}", hint="Use prd, design, plan or context.")


def review_prd(project: Path | None) -> PrdReview:
    """The G1 summary of the current `prd.md`."""
    return _review(_store(project))


def approve_prd(project: Path | None, *, sha256: str) -> bool:
    """Record G1 for the PRD the user reviewed; False if it was already approved."""
    store = _store(project)
    with store.lock():
        review = _review(store)
        if review.sha256 != sha256:
            raise UsageError(
                "prd.md changed after it was shown; nothing was approved",
                hint="Run `aipm approve prd` again to review the current file.",
            )
        if review.stale:
            raise UsageError(
                "prd.md is stale: requirements.yaml changed after the PRD was written",
                hint="Run `aipm discover` to regenerate the PRD.",
            )
        if review.blocking:
            raise UsageError(
                f"G1 is blocked by open questions: {', '.join(review.blocking)}",
                hint="Answer them or turn them into assumptions with `aipm discover`.",
            )
        return record_approval(store, ApprovalGate.G1, PRD_FILE, sha256)
