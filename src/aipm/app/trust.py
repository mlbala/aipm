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
from aipm.domain.errors import PolicyViolation
from aipm.domain.models import RepoId
from aipm.state.layout import repo_id
from aipm.state.trust_store import (
    FileTrustStore,
    default_trust_store,
    hash_surface,
    render_surface,
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


def inspect(context: TrustContext, *, store: FileTrustStore | None = None) -> TrustReport:
    """Compute the surface and its hash, and whether this user trusts it.

    Raises `PolicyViolation` (exit 6) if the surface fails the command policy.
    """
    trust_store = store if store is not None else default_trust_store()
    surface = trust_store.surface(context.loaded.config)
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
    trust_store = store if store is not None else default_trust_store()
    report = inspect(load(project), store=trust_store)
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
    trust_store = store if store is not None else default_trust_store()
    return trust_store.revoke(repo_id(root))
