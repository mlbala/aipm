"""`aipm trust`: show the execution surface and record trust (SECURITY.md §6).

Trust is recorded only by `confirm`, which needs the first 12 hex characters of the current
surface hash: the CLI passes them after an interactive "yes", or the user passes them with
`--confirm`. Nothing here reads `--yes`, so a blanket yes can never grant trust.
"""

import re
import secrets
from dataclasses import dataclass, replace
from pathlib import Path
from typing import Any

from aipm.app.workspace import find_repo_root, require_initialized
from aipm.config.loader import LoadedConfig, load_config
from aipm.config.schema import Config
from aipm.domain.errors import PolicyViolation
from aipm.domain.models import RepoId
from aipm.execution import git
from aipm.state.layout import repo_id
from aipm.state.trust_store import (
    CARGO_DIR,
    MAX_TOOLCHAIN_BYTES,
    PYPROJECT,
    TOOLCHAIN_FILES,
    Committed,
    FileTrustStore,
    default_trust_store,
    hash_surface,
    pin_toolchain,
    render_surface,
    select_toolchain,
)

_HASH_PREFIX = re.compile(r"[0-9a-f]{12,64}")


@dataclass(frozen=True, slots=True)
class TrustReport:
    """A repository's execution surface, its hash, and whether this user trusts it."""

    repo_root: str
    repo_id: str
    surface: dict[str, Any]
    surface_hash: str
    trusted: bool
    lines: tuple[str, ...]
    warnings: tuple[str, ...]

    def to_data(self) -> dict[str, object]:
        """The `--json` payload."""
        return {
            "repo": self.repo_root,
            "repo_id": self.repo_id,
            "surface_hash": self.surface_hash,
            "trusted": self.trusted,
            "surface": self.surface,
            "warnings": list(self.warnings),
        }


def _summary(surface: dict[str, Any]) -> str:
    with_argv = sorted(name for name, gate in surface["gates"].items() if "argv" in gate)
    prepare = surface["prepare"]
    parts = [f"gates with argv: {', '.join(with_argv) or 'none'}"]
    parts.append(f"prepare: {' '.join(prepare['argv']) if prepare else 'none'}")
    return "; ".join(parts)


@dataclass(frozen=True, slots=True)
class TrustContext:
    """The repository and its loaded configuration (with the warnings to print first)."""

    root: Path
    loaded: LoadedConfig

    @property
    def warnings(self) -> tuple[str, ...]:
        """Config warnings, printed even when the surface turns out to be untrustable."""
        return self.loaded.warnings


def load(project: Path | None) -> TrustContext:
    """Find the initialized repository at (or above) `project` and load its configuration."""
    root = find_repo_root(project)
    require_initialized(root)
    return TrustContext(root=root, loaded=load_config(root))


def committed_toolchain(root: Path) -> Committed:
    """The repository's committed toolchain files at the root (and in `.cargo/`), from `HEAD`:
    what a clone or a pull brings (ADR-0032). The working tree is not read: an agent's change
    there is the post-change checks' to judge (a dependency violation), which must not turn
    into a question to trust the surface again."""
    head = git.committed_head(root)
    if head is None:
        return {}
    top = {e.name: e for e in git.list_tree(root, head)}
    picked = {want: top[name] for want, name in
              select_toolchain(top, (*TOOLCHAIN_FILES, PYPROJECT, CARGO_DIR)).items()}  # fmt: skip
    cargo = picked.get(CARGO_DIR)
    if cargo is not None and cargo.kind == "tree":
        inner = {e.name: e for e in git.list_tree(root, cargo.object_id)}
        wanted = tuple(rel.split("/", 1)[1] for rel in TOOLCHAIN_FILES if rel.startswith(".cargo/"))
        for want, name in select_toolchain(inner, wanted).items():
            picked[f"{CARGO_DIR}/{want}"] = inner[name]
    committed: Committed = {}
    for rel, entry in picked.items():
        data: bytes | None = None
        if entry.kind == "blob" and entry.mode in ("100644", "100755"):
            raw, cut = git.read_object(root, entry.object_id, max_bytes=MAX_TOOLCHAIN_BYTES)
            data = None if cut else raw
        committed[rel] = (entry.mode, data)
    return committed


def repository_surface(store: FileTrustStore, cfg: Config, root: Path) -> dict[str, Any]:
    """The execution surface of the repository at `root`: `cfg`'s, its agent hooks and MCP
    servers when bare mode is off, and the hashes of its committed toolchain files. The command
    policy is checked first, so a refused argv exits 6 before git is asked anything."""
    surface = store.surface(cfg, root=root)
    toolchain = pin_toolchain(committed_toolchain(root))
    return {**surface, "toolchain_files": toolchain} if toolchain else surface


def inspect(context: TrustContext, *, store: FileTrustStore | None = None) -> TrustReport:
    """Compute the surface and its hash, and whether this user trusts it.

    Raises `PolicyViolation` (exit 6) if the surface fails the command policy.
    """
    trust_store = store if store is not None else default_trust_store(context.root)
    surface = repository_surface(trust_store, context.loaded.config, context.root)
    digest = hash_surface(surface)
    rid = repo_id(context.root)
    return TrustReport(
        repo_root=str(context.root),
        repo_id=rid,
        surface=surface,
        surface_hash=digest,
        trusted=trust_store.is_trusted(rid, digest),
        lines=tuple(render_surface(surface, digest)),
        warnings=context.warnings,
    )


def confirm(
    project: Path | None, value: str, *, store: FileTrustStore | None = None
) -> TrustReport:
    """Record trust if `value` starts the current surface hash (12 to 64 hex characters).

    `--confirm` passes at least the 12 characters SECURITY.md §6 asks for; the interactive flow
    passes the full hash of the surface it showed, so a surface that changed in between, even
    one crafted to share a prefix, is refused.
    """
    context = load(project)
    trust_store = store if store is not None else default_trust_store(context.root)
    report = inspect(context, store=trust_store)
    given = value.strip().lower()
    if not _HASH_PREFIX.fullmatch(given):
        raise PolicyViolation(
            "--confirm takes the first 12 (or more) hex characters of the surface hash",
            hint="Run `aipm trust --show` to see the surface and its hash.",
        )
    if not secrets.compare_digest(given, report.surface_hash[: len(given)]):
        raise PolicyViolation(
            "--confirm does not match the current surface hash (wrong or stale)",
            hint="Run `aipm trust --show` and review the surface again.",
        )
    trust_store.trust(RepoId(report.repo_id), report.surface_hash, _summary(report.surface))
    return replace(report, trusted=True)


def revoke(project: Path | None, *, store: FileTrustStore | None = None) -> bool:
    """Remove this user's trust for the repository; returns whether there was any."""
    root = find_repo_root(project)
    trust_store = store if store is not None else default_trust_store(root)
    return trust_store.revoke(repo_id(root))


def require_trusted(
    root: Path, loaded: LoadedConfig, *, command: str, store: FileTrustStore | None = None
) -> TrustReport:
    """Exit 6 unless this user trusts the repository's current execution surface.

    For the commands that hand gate argv to an agent (`prompt`, `sync-context`), which the
    agent then runs outside aipm's sandbox (SECURITY.md §6 rule 3). A surface that fails the
    command policy can never be trusted, and exits 6 with the reason.
    """
    report = inspect(TrustContext(root=root, loaded=loaded), store=store)
    if not report.trusted:
        raise PolicyViolation(
            f"aipm {command} hands this repository's gate commands to your coding agent, and you "
            "have not trusted them",
            hint="Review them with `aipm trust --show`, then run `aipm trust`.",
        )
    return report
