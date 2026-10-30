"""The attempt snapshot a task starts from, and the check policy built from config (ADR-0021).

`aipm prompt` takes the snapshot when a task starts; `aipm verify` compares the tree with it;
`aipm task reset` removes it.
"""

from pathlib import Path

from aipm.config.schema import Config
from aipm.domain.models import ChangeSet
from aipm.execution.git import ChangeInputs, change_set, integrity_snapshot, snapshot_files
from aipm.security.diff_checks import CheckPolicy, is_watched, needs_content
from aipm.state.attempts import AttemptSnapshot, WriteLedger, new_snapshot, save_snapshot


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
    )
