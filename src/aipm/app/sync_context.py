"""`aipm sync-context`: the managed blocks of `AGENTS.md` and `CLAUDE.md` (ARCHITECTURE §10.2).

The blocks carry gate argv that the user's agent runs outside aipm's sandbox, so `review`,
`write` and `approve` need trust (exit 6, SECURITY.md §6 rule 3). They also need the approved,
current PRD and design (G1, G2); there is no `--accept-stale` here.

- `review` renders every block and diffs it against the file.
- `write` writes the changed files, under the lock, only if nothing changed since the review,
  and only when the user confirmed the diff or `aipm approve context` approved those exact blocks
  (gate `context`, pinned to each block's sha256). It records the approval of what it wrote.
- `approve` records approval of the reviewed blocks without writing (`aipm approve context`).
- `check` (`--check`, for CI) exits 3 on drift. It needs no trust: it writes nothing and returns
  only file names, never a block or an argv (ADR-0017). The argv still passes `compile_gate`.

Only text between the aipm markers changes; everything else in the files stays byte for byte,
and files are never read or written through a link (`aipm.state.repo_files`).
"""

import difflib
import hashlib
from collections.abc import Sequence
from dataclasses import dataclass
from pathlib import Path

from aipm.adapters.registry import get_adapter, parse_tool
from aipm.app import runtime
from aipm.app.approve import load_approvals, record_approval
from aipm.app.project_context import build_context
from aipm.app.snapshot import read_snapshot
from aipm.app.trust import require_trusted
from aipm.app.workspace import find_repo_root, require_initialized
from aipm.config.loader import LoadedConfig, load_config
from aipm.context.managed_block import extract_block, replace_block
from aipm.domain.errors import (
    HumanInputRequired,
    PolicyViolation,
    UsageError,
    VerificationFailed,
)
from aipm.domain.models import ApprovalGate, GeneratedFile, ToolName
from aipm.domain.phase import InputState, plan_inputs
from aipm.state.repo_files import read_repo_bytes, write_repo_bytes
from aipm.state.store import FileStateStore, normalized_sha256, open_store


@dataclass(frozen=True, slots=True)
class FileChange:
    """One context file: its managed block now and as aipm would write it."""

    path: str
    current: bytes | None
    document: str
    block: str
    block_sha256: str
    old_block: str | None
    approved: bool

    @property
    def changed(self) -> bool:
        """Whether the managed block differs from the generated one."""
        return self.old_block != self.block

    @property
    def action(self) -> str:
        """What a write does to the file."""
        if self.current is None:
            return "create"
        return "append" if self.old_block is None else "replace"

    def diff(self) -> list[str]:
        """A unified diff of the managed block (repository text, so print it sanitized)."""
        old = [] if self.old_block is None else self.old_block.splitlines()
        return list(
            difflib.unified_diff(
                old,
                self.block.splitlines(),
                fromfile=f"a/{self.path} (managed block)",
                tofile=f"b/{self.path} (managed block)",
                lineterm="",
            )
        )


@dataclass(frozen=True, slots=True)
class ContextReview:
    """Every context file of the chosen tools, and what writing would change."""

    repo_root: str
    tools: tuple[str, ...]
    files: tuple[FileChange, ...]
    warnings: tuple[str, ...]

    @property
    def changed(self) -> tuple[FileChange, ...]:
        """The files whose managed block would change."""
        return tuple(f for f in self.files if f.changed)

    @property
    def digest(self) -> str:
        """Pins what was reviewed: every block and every file's current bytes."""
        h = hashlib.sha256()
        for f in self.files:
            current = b"\x00missing" if f.current is None else hashlib.sha256(f.current).digest()
            h.update(f.path.encode() + b"\x00" + f.block_sha256.encode() + b"\x00" + current)
        return h.hexdigest()

    def to_data(self) -> dict[str, object]:
        """The `--json` payload."""
        return {
            "repo": self.repo_root,
            "tools": list(self.tools),
            "files": [
                {
                    "path": f.path,
                    "changed": f.changed,
                    "action": f.action,
                    "block_sha256": f.block_sha256,
                    "approved": f.approved,
                }
                for f in self.files
            ],
            "warnings": list(self.warnings),
        }


@dataclass(frozen=True, slots=True)
class SyncResult:
    """What a write or an approval did."""

    written: tuple[str, ...] = ()
    recorded: tuple[str, ...] = ()

    def to_data(self) -> dict[str, object]:
        """The `--json` payload."""
        return {"written": list(self.written), "recorded": list(self.recorded)}


def _tools(names: Sequence[str], loaded: LoadedConfig) -> tuple[ToolName, ...]:
    chosen = [parse_tool(n, loaded.config.dispatch.default_tool) for n in names]
    tools = tuple(dict.fromkeys(chosen or [loaded.config.dispatch.default_tool]))
    for tool in tools:
        get_adapter(tool)  # exit 2 for a tool that has no adapter yet
    return tools


def _decode(path: str, data: bytes | None) -> str:
    if data is None:
        return ""
    try:
        return data.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise UsageError(
            f"{path} is not valid UTF-8 (byte {exc.start}); nothing was written",
            hint=f"Fix the encoding of {path}, then run aipm again.",
        ) from None


def _generated(
    loaded: LoadedConfig, store: FileStateStore, tools: tuple[ToolName, ...], *, detail: bool
) -> list[GeneratedFile]:
    cfg = loaded.config
    snapshot, _ = read_snapshot(
        store, coverage_threshold=cfg.discover.coverage_threshold, trusted=False
    )
    bad = [c.reason for c in plan_inputs(snapshot) if c.state is not InputState.OK]
    if bad:
        raise UsageError(
            "aipm sync-context renders only the approved, current PRD and design: "
            + "; ".join(bad),
            hint="Approve them (`aipm approve prd`, `aipm approve design`) or regenerate them.",
        )
    ctx = build_context(snapshot, cfg, detail=detail)
    files: dict[str, GeneratedFile] = {}
    for tool in tools:
        for generated in get_adapter(tool).context_files(ctx):
            files.setdefault(generated.path, generated)
    return list(files.values())


def _review(
    root: Path,
    loaded: LoadedConfig,
    store: FileStateStore,
    tools: tuple[ToolName, ...],
    *,
    detail: bool = True,
) -> ContextReview:
    approvals = load_approvals(store)
    changes: list[FileChange] = []
    for generated in _generated(loaded, store, tools, detail=detail):
        if store.redactor.contains_secret(generated.block):
            # Checked before anything is shown: a gate argv from the user config, or a .pm/
            # file edited by hand, could carry a secret into a committed file (SECURITY.md §8).
            raise PolicyViolation(
                f"the generated {generated.path} block would contain a secret; nothing was "
                "shown or written",
                hint="Remove the secret from the gate commands in your config or from .pm/.",
            )
        current = read_repo_bytes(root, generated.path)
        text = _decode(generated.path, current)
        block_sha = normalized_sha256(generated.block.encode("utf-8"))
        changes.append(
            FileChange(
                path=generated.path,
                current=current,
                document=replace_block(text, generated.block, name=generated.path),
                block=generated.block,
                block_sha256=block_sha,
                old_block=extract_block(text, name=generated.path),
                approved=approvals.has(ApprovalGate.CONTEXT, generated.path, block_sha),
            )
        )
    return ContextReview(str(root), tuple(t.value for t in tools), tuple(changes), loaded.warnings)


@dataclass(frozen=True, slots=True)
class _Session:
    root: Path
    loaded: LoadedConfig
    store: FileStateStore
    tools: tuple[ToolName, ...]


def _open(project: Path | None, tools: Sequence[str], *, trust: bool) -> _Session:
    root = find_repo_root(project)
    require_initialized(root)
    loaded = load_config(root)
    chosen = _tools(tools, loaded)
    if trust:
        require_trusted(root, loaded, command="sync-context")
    return _Session(root, loaded, open_store(root, redactor=runtime.user_redactor(root)), chosen)


def review(project: Path | None, tools: Sequence[str] = ()) -> ContextReview:
    """Render every managed block and compare it with the files (needs trust)."""
    s = _open(project, tools, trust=True)
    return _review(s.root, s.loaded, s.store, s.tools)


def check(project: Path | None, tools: Sequence[str] = ()) -> tuple[str, ...]:
    """`--check`: the up-to-date files, or `VerificationFailed` (exit 3) naming the others."""
    s = _open(project, tools, trust=False)
    result = _review(s.root, s.loaded, s.store, s.tools, detail=False)
    drift = [f.path for f in result.changed]
    if drift:
        raise VerificationFailed(
            f"out of date: {', '.join(drift)}",
            hint="Run `aipm sync-context` to review and write them.",
            data={"drift": drift},
        )
    return tuple(f.path for f in result.files)


def _reviewed_again(s: _Session, expected: str) -> ContextReview:
    current = _review(s.root, s.loaded, s.store, s.tools)
    if current.digest != expected:
        raise UsageError(
            "the context files or their sources changed after they were shown; nothing was "
            "written or approved",
            hint="Run the command again to review the current state.",
        )
    return current


def write(
    project: Path | None, tools: Sequence[str] = (), *, expected: str, confirmed: bool
) -> SyncResult:
    """Write the changed blocks the user just confirmed, or that are approved (needs trust)."""
    s = _open(project, tools, trust=True)
    with s.store.lock():
        current = _reviewed_again(s, expected)
        pending = [f.path for f in current.changed if not f.approved]
        if pending and not confirmed:
            raise HumanInputRequired(
                f"the new managed blocks of {', '.join(pending)} are not approved",
                hint="Review the diff, then run `aipm approve context --yes` and "
                "`aipm sync-context`, or run `aipm sync-context` in a terminal.",
            )
        written: list[str] = []
        recorded: list[str] = []
        for f in current.changed:
            write_repo_bytes(s.root, f.path, f.document.encode("utf-8"), expected=f.current)
            written.append(f.path)
            if record_approval(s.store, ApprovalGate.CONTEXT, f.path, f.block_sha256):
                recorded.append(f.path)
    return SyncResult(tuple(written), tuple(recorded))


def approve(project: Path | None, tools: Sequence[str] = (), *, expected: str) -> SyncResult:
    """Record approval of the reviewed blocks (`aipm approve context`); writes no file."""
    s = _open(project, tools, trust=True)
    with s.store.lock():
        current = _reviewed_again(s, expected)
        recorded = [
            f.path
            for f in current.files
            if record_approval(s.store, ApprovalGate.CONTEXT, f.path, f.block_sha256)
        ]
    return SyncResult(recorded=tuple(recorded))
