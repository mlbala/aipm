"""`aipm doctor`: tool versions, capabilities, sandbox, which keys are set.

Read-only and LLM-free (P-11). Missing tools are listed, not errors. Key variables are reported
as present or absent, never their values. Each tool runs as `<absolute path> --version` through
`run_safe`, from an empty temporary directory, with a constructed environment and a short
timeout; its output is sanitized before it is shown.
"""

import os
import platform
import shutil
import tempfile
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path

from aipm import __version__
from aipm.app.workspace import find_repo_root
from aipm.config.loader import load_config
from aipm.config.schema import Config
from aipm.domain.errors import AipmError, LockHeld
from aipm.domain.models import ArtifactKind
from aipm.execution.process import build_env, run_safe
from aipm.security.sanitize import sanitize_text
from aipm.state.layout import ARTIFACT_FILES, pm_root, repo_id
from aipm.state.store import open_store
from aipm.state.trust_store import default_trust_store, hash_surface

TOOLS = (
    "git", "uv", "claude", "codex", "copilot", "gemini", "srt", "semgrep", "gitleaks",
    "osv-scanner", "trivy",
)  # fmt: skip
KEY_VARIABLES = ("ANTHROPIC_API_KEY", "OPENAI_API_KEY", "GEMINI_API_KEY", "GITHUB_TOKEN")
VERSION_TIMEOUT_S = 10.0
_LOADABLE = (
    ArtifactKind.REQUIREMENTS,
    ArtifactKind.PRD,
    ArtifactKind.ARCHITECTURE,
    ArtifactKind.THREAT_MODEL,
    ArtifactKind.TASKS,
    ArtifactKind.APPROVALS,
    ArtifactKind.REPO_MAP,
)


@dataclass(frozen=True, slots=True)
class DoctorReport:
    """Everything doctor found, as JSON-ready data and as lines for the terminal."""

    data: dict[str, object]
    lines: tuple[str, ...]


def _clean(text: str, limit: int = 200) -> str:
    return sanitize_text(text, source="doctor").text.replace("\n", " ").strip()[:limit]


def _tool(name: str, workdir: Path) -> dict[str, object]:
    path = shutil.which(name)
    if path is None:
        return {"name": name, "found": False, "path": None, "version": None}
    try:
        result = run_safe(
            [path, "--version"],
            cwd=workdir,
            env=build_env(),
            timeout_s=VERSION_TIMEOUT_S,
            max_output_bytes=4096,
        )
    except (AipmError, OSError) as exc:
        error = _clean(str(exc))
        return {"name": name, "found": True, "path": _clean(path), "version": None, "error": error}
    output = (result.stdout or result.stderr).decode("utf-8", errors="replace")
    first = next((line for line in output.splitlines() if line.strip()), "")
    version = _clean(first) if result.returncode == 0 and first else None
    return {"name": name, "found": True, "path": _clean(path), "version": version}


def _artifacts(root: Path) -> dict[str, str]:
    store = open_store(root)
    report: dict[str, str] = {}
    for kind in _LOADABLE:
        name = ARTIFACT_FILES[kind]
        if not store.exists(kind):
            report[name] = "missing"
            continue
        try:
            store.load(kind)
        except AipmError as exc:
            report[name] = _clean(exc.message, 500)
        else:
            report[name] = "ok"
    return report


def _lock(root: Path) -> dict[str, object]:
    try:
        with open_store(root).lock():
            pass
    except LockHeld as exc:
        return {"held": True, "detail": _clean(exc.message)}
    except AipmError as exc:
        return {"held": None, "detail": _clean(exc.message)}
    return {"held": False, "detail": None}


def _trust(root: Path, config: Config) -> dict[str, object]:
    try:
        store = default_trust_store(root)
        digest = hash_surface(store.surface(config))
        trusted = store.is_trusted(repo_id(root), digest)
    except AipmError as exc:
        return {"trusted": False, "surface_hash": None, "error": _clean(exc.message, 500)}
    return {"trusted": trusted, "surface_hash": digest, "error": None}


def run(project: Path | None, *, env: Mapping[str, str] | None = None) -> DoctorReport:
    """Run the use case."""
    environ = os.environ if env is None else env
    with tempfile.TemporaryDirectory(prefix="aipm-doctor-") as scratch:
        tools = [_tool(name, Path(scratch)) for name in TOOLS]
    try:
        root: Path | None = find_repo_root(project)
    except AipmError:
        root = None
    config_data: dict[str, object]
    config: Config | None = None
    warnings: list[str] = []
    try:
        loaded = load_config(root)
    except AipmError as exc:
        config_data = {"ok": False, "error": _clean(exc.message, 500), "sources": []}
    else:
        config = loaded.config
        warnings = [_clean(w, 500) for w in loaded.warnings]
        config_data = {"ok": True, "error": None, "sources": list(loaded.sources)}
    extra_keys: list[str] = [config.llm.api_key_env] if config else []
    keys = {name: bool(environ.get(name)) for name in sorted({*KEY_VARIABLES, *extra_keys})}
    initialized = root is not None and pm_root(root).is_dir()
    sections = _Sections(
        tools=tools,
        keys=keys,
        root=None if root is None else str(root),
        initialized=initialized,
        config=config_data,
        warnings=warnings,
        schema=_artifacts(root) if root is not None and initialized else {},
        lock=_lock(root) if root is not None and initialized else None,
        trust=_trust(root, config) if root is not None and initialized and config else None,
        srt=any(t["name"] == "srt" and t["found"] for t in tools),
        require_sandbox=bool(config and config.security.require_sandbox),
    )
    return DoctorReport(data=sections.data(), lines=tuple(sections.lines()))


@dataclass(frozen=True, slots=True)
class _Sections:
    tools: list[dict[str, object]]
    keys: dict[str, bool]
    root: str | None
    initialized: bool
    config: dict[str, object]
    warnings: list[str]
    schema: dict[str, str]
    lock: dict[str, object] | None
    trust: dict[str, object] | None
    srt: bool
    require_sandbox: bool

    def data(self) -> dict[str, object]:
        return {
            "aipm": {"version": __version__, "python": platform.python_version()},
            "tools": self.tools,
            "keys": self.keys,
            "repo": None
            if self.root is None
            else {"root": self.root, "initialized": self.initialized},
            "config": {**self.config, "warnings": self.warnings},
            "schema": self.schema,
            "lock": self.lock,
            "trust": self.trust,
            "sandbox": {"srt": self.srt, "require_sandbox": self.require_sandbox},
            "plugins": {
                "enabled": False,
                "loaded": [],
                "note": "entry-point plugins arrive in v0.4",
            },
        }

    def lines(self) -> list[str]:
        lines = [f"aipm {__version__} (Python {platform.python_version()})", "", "Tools:"]
        for tool in self.tools:
            if not tool["found"]:
                lines.append(f"  {tool['name']!s:<12} missing")
                continue
            version = tool["version"] or "version unknown"
            lines.append(f"  {tool['name']!s:<12} {version}  ({tool['path']})")
        lines.append("API key variables (values are never shown):")
        lines.extend(
            f"  {name}: {'set' if found else 'not set'}" for name, found in self.keys.items()
        )
        if self.root is None:
            lines.append("Repository: not inside a git repository")
        else:
            state = "initialized" if self.initialized else "not initialized (run `aipm init`)"
            lines.append(f"Repository: {self.root} ({state})")
        lines.append(f"Config: {'ok' if self.config['ok'] else self.config['error']}")
        lines.extend(f"  warning: {warning}" for warning in self.warnings)
        if self.schema:
            lines.append(".pm/ files:")
            lines.extend(f"  {name}: {status}" for name, status in self.schema.items())
        if self.lock is not None:
            held = self.lock["held"]
            state = (
                "free"
                if held is False
                else f"held: {self.lock['detail']}"
                if held
                else str(self.lock["detail"])
            )
            lines.append(f"Lock: {state}")
        if self.trust is not None:
            if self.trust["error"]:
                lines.append(f"Trust: cannot compute the surface: {self.trust['error']}")
            else:
                state = "trusted" if self.trust["trusted"] else "not trusted (run `aipm trust`)"
                lines.append(f"Trust: {state}, surface {str(self.trust['surface_hash'])[:12]}")
        lines.append(
            f"Sandbox: srt {'found' if self.srt else 'not found'}; "
            f"require_sandbox={self.require_sandbox}"
        )
        lines.append("Plugins: off (entry-point plugins arrive in v0.4)")
        return lines
