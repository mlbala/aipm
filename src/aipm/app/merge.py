"""`aipm merge`: fast-forward your branch to the integration branch (ARCHITECTURE §12.2,
SECURITY.md §11).

`plan` shows `git log --oneline <branch>..<integration>` and changes nothing; the CLI asks for
confirmation (a non-interactive run exits 4), then `apply` checks everything again under the
`.pm/` lock and moves the branch only if neither branch moved since the log was shown:

- the branch checked out here: `git merge --ff-only` (the working tree must be clean);
- a branch checked out nowhere: a compare-and-swap `update-ref`;
- a branch checked out in another worktree, or one of aipm's own: refused (exit 2).

Fast-forward only, never a merge commit, never a push. Same preconditions as `build`: trust,
`dispatch.enabled`, an approved plan that is not stale, a clean tree.
"""

import os
from dataclasses import dataclass, field
from pathlib import Path

from aipm.app import runtime
from aipm.app.approve import require_inputs
from aipm.app.build import require_clean
from aipm.app.snapshot import read_snapshot
from aipm.app.trust import require_trusted
from aipm.app.workspace import find_repo_root, require_initialized
from aipm.config.loader import load_config
from aipm.domain.errors import UsageError
from aipm.domain.phase import prompt_inputs
from aipm.execution import git
from aipm.execution.worktree import INTEGRATION_PREFIX, check_integration_branch
from aipm.security.sanitize import sanitize_text

MAX_LOG_LINES = 200


@dataclass(frozen=True, slots=True)
class MergePlan:
    """What `aipm merge` would do. `lines` are commit subjects: repository text."""

    target: str
    integration: str
    target_sha: str
    integration_sha: str
    lines: tuple[str, ...] = ()
    more: bool = False
    here: bool = False
    warnings: tuple[str, ...] = field(default_factory=tuple[str, ...])

    @property
    def nothing(self) -> bool:
        """The branch is already at the integration branch's head."""
        return self.target_sha == self.integration_sha

    def to_data(self) -> dict[str, object]:
        """The `--json` payload."""
        return {
            "into": self.target, "integration": self.integration,
            "from": self.target_sha, "to": self.integration_sha,
            "commits": list(self.lines), "more": self.more, "nothing": self.nothing,
            "warnings": list(self.warnings),
        }  # fmt: skip


@dataclass(frozen=True, slots=True)
class MergeResult:
    """The branch moved from `before` to `after`."""

    target: str
    before: str
    after: str
    commits: int

    def to_data(self) -> dict[str, object]:
        """The `--json` payload."""
        return {"into": self.target, "from": self.before, "to": self.after, "merged": True,
                "commits": self.commits}  # fmt: skip


def _plan(root: Path, into: str | None, warnings: tuple[str, ...]) -> MergePlan:
    loaded = load_config(root)
    cfg = loaded.config
    integration = check_integration_branch(cfg.git.integration_branch)
    target = into if into is not None else git.current_branch(root)
    if target is None:
        raise UsageError("HEAD is detached", hint="Pass --into BRANCH, or check a branch out.")
    git.check_branch(target)
    if target.startswith(INTEGRATION_PREFIX):
        raise UsageError(f"{target} is one of aipm's own branches; merge into one of yours")
    integration_sha = git.ref_sha(root, integration)
    if integration_sha is None:
        raise UsageError(f"there is no {integration} yet", hint="Run `aipm build` first.")
    target_sha = git.ref_sha(root, target)
    if target_sha is None:
        raise UsageError(f"there is no branch {target}")
    where = [os.path.realpath(p) for p in git.checked_out(root, target)]
    here = os.path.realpath(root) in where
    if where and not here:
        raise UsageError(
            f"{target} is checked out in {where[0]}",
            hint="Merge from that worktree, or switch it to another branch first.",
        )
    if target_sha == integration_sha:
        return MergePlan(target, integration, target_sha, integration_sha, here=here,
                         warnings=warnings)  # fmt: skip
    if not git.is_ancestor(root, target_sha, integration_sha):
        raise UsageError(
            f"{target} has commits that {integration} does not, so it cannot be fast-forwarded",
            hint=f"Merge by hand, for example `git merge {integration}`, after reviewing it.",
        )
    raw, more = git.log_oneline(root, target_sha, integration_sha, limit=MAX_LOG_LINES)
    lines = tuple(" ".join(sanitize_text(line, source="git log").text.split()) for line in raw)
    return MergePlan(target, integration, target_sha, integration_sha, lines, more, here,
                     warnings)  # fmt: skip


def _preconditions(root: Path) -> tuple[str, ...]:
    loaded = load_config(root)
    cfg = loaded.config
    require_trusted(root, loaded, command="merge")
    if not cfg.dispatch.enabled:
        raise UsageError("dispatch is turned off (dispatch.enabled: false)")
    store = runtime.open_repo_store(root)
    snapshot, _ = read_snapshot(
        store, coverage_threshold=cfg.discover.coverage_threshold, trusted=True
    )
    warnings = require_inputs(store, "merge", prompt_inputs(snapshot), accept_stale=False)
    require_clean(root)
    return (*loaded.warnings, *warnings)


def plan(project: Path | None, *, into: str | None) -> MergePlan:
    """What a merge would do; changes nothing."""
    root = find_repo_root(project)
    require_initialized(root)
    warnings = _preconditions(root)
    return _plan(root, into, warnings)


def apply(project: Path | None, shown: MergePlan) -> MergeResult:
    """Fast-forward the branch, if nothing moved since `shown` was shown."""
    root = find_repo_root(project)
    require_initialized(root)
    store = runtime.open_repo_store(root)
    with store.lock():
        _preconditions(root)
        now = _plan(root, shown.target, shown.warnings)
        if (now.target_sha, now.integration_sha) != (shown.target_sha, shown.integration_sha):
            raise UsageError(
                "the branches moved since the log was shown; nothing was merged",
                hint="Run `aipm merge` again and review the new log.",
            )
        if now.nothing:
            raise UsageError(f"{now.target} is already at {now.integration}")
        if now.here:
            git.merge_ff_only(root, now.integration_sha)
        else:
            git.update_ref(root, now.target, now.integration_sha, now.target_sha)
    return MergeResult(now.target, now.target_sha, now.integration_sha, len(now.lines))
