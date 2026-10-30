"""`aipm init`: create `.pm/`, detect the stack, write the repo map, run trust.

The repo-level `.pm/config.yaml` gets only repo-ok settings: the project name, the stack
template and its gate menu, and the default tool. `--provider` names a user-only key, so it is
validated and reported, never written into the repository (SECURITY.md §6 rule 5). Trust is
offered by the CLI afterwards and recorded only through `aipm.app.trust.confirm`.
"""

import re
from dataclasses import dataclass
from pathlib import Path

from aipm.app import runtime
from aipm.app import trust as trust_use_case
from aipm.app.repo_map import repo_map_doc, scan_repo
from aipm.app.workspace import find_repo_root
from aipm.config.loader import load_config, user_config_path
from aipm.config.schema import Config, Provider
from aipm.config.stacks import available_stacks, load_stack
from aipm.domain.errors import PolicyViolation, UsageError
from aipm.domain.models import ArtifactKind, Mode, ToolName
from aipm.state.layout import ARTIFACT_FILES, GITIGNORE_FILE

_PYTHON_MANIFESTS = frozenset({"pyproject.toml", "setup.py", "setup.cfg"})


@dataclass(frozen=True, slots=True)
class InitResult:
    """What `aipm init` did, for the CLI to report."""

    repo_root: str
    mode: Mode
    detected_stack: str | None
    stack_template: str | None
    written: tuple[str, ...]
    kept: tuple[str, ...]
    notes: tuple[str, ...]
    warnings: tuple[str, ...]
    trust: trust_use_case.TrustReport | None

    def to_data(self) -> dict[str, object]:
        """The `--json` payload."""
        return {
            "repo": self.repo_root,
            "mode": self.mode.value,
            "detected_stack": self.detected_stack,
            "stack_template": self.stack_template,
            "written": list(self.written),
            "kept": list(self.kept),
            "notes": list(self.notes),
            "surface_hash": None if self.trust is None else self.trust.surface_hash,
            "trusted": False if self.trust is None else self.trust.trusted,
        }


def detect_stack(manifests: tuple[str, ...]) -> str | None:
    """Name the stack from the manifests at the repository root."""
    names = set(manifests)
    if "uv.lock" in names:
        return "python-uv"
    if names & _PYTHON_MANIFESTS or any(name.startswith("requirements") for name in names):
        return "python-pip"
    if "package.json" in names:
        return "node-pnpm" if "pnpm-lock.yaml" in names else "node-npm"
    return None


def project_name(root: Path) -> str | None:
    """A `project.name` derived from the directory name, if one fits the schema."""
    name = re.sub(r"[^a-z0-9\-]+", "-", root.name.casefold()).strip("-")[:64]
    return name if re.fullmatch(r"[a-z0-9][a-z0-9\-]{1,63}", name) else None


def _check_flags(provider: str | None, tool: str | None) -> list[str]:
    notes: list[str] = []
    if provider is not None:
        if provider not in {p.value for p in Provider}:
            raise UsageError(
                f"unknown provider {provider!r}", hint="Use anthropic or openai-compatible."
            )
        notes.append(
            f"llm.provider is a user-only key, so it is not written to .pm/config.yaml. "
            f"Set `llm: {{provider: {provider}}}` in {user_config_path()}."
        )
    if tool is not None and tool not in {t.value for t in ToolName}:
        raise UsageError(f"unknown tool {tool!r}", hint="Use claude, codex, copilot or gemini.")
    return notes


def run(
    project: Path | None, *, provider: str | None, tool: str | None, stack: str | None, force: bool
) -> InitResult:
    """Run the use case."""
    root = find_repo_root(project)
    notes = _check_flags(provider, tool)
    if stack is not None:
        load_stack(stack)  # an unknown name exits 2 here, before anything is written
    store = runtime.open_repo_store(root)
    if store.root.exists() and not force:
        raise UsageError(
            f"{store.root} already exists", hint="Use `aipm init --force` to re-initialize."
        )

    defaults = load_config(None).config
    scan = scan_repo(root, max_input_bytes=defaults.security.max_input_kib * 1024)
    detected = detect_stack(scan.manifests)
    template_name = stack
    if template_name is None and detected is not None:
        if detected in available_stacks():
            template_name = detected
        else:
            notes.append(
                f"detected the {detected} stack, which has no built-in template yet, so no "
                "gates were copied (ARCHITECTURE §13.1)."
            )

    settings: dict[str, object] = {}
    name = project_name(root)
    if name is not None:
        settings["project"] = {"name": name}
    if template_name is not None:
        template = load_stack(template_name)
        settings["stack_template"] = template_name
        settings.update(template.model_dump(mode="json", exclude_none=True))
    if tool is not None:
        settings["dispatch"] = {"default_tool": tool}
    config = Config.model_validate(settings)

    kept = tuple(
        sorted(
            file
            for kind, file in ARTIFACT_FILES.items()
            if kind not in (ArtifactKind.CONFIG, ArtifactKind.REPO_MAP) and store.exists(kind)
        )
    )
    with store.lock():
        store.write_gitignore()
        store.save(config)
        store.save(repo_map_doc(scan, stack_template=template_name))
    written = (
        GITIGNORE_FILE,
        ARTIFACT_FILES[ArtifactKind.CONFIG],
        ARTIFACT_FILES[ArtifactKind.REPO_MAP],
    )
    context = trust_use_case.load(root)
    try:
        report: trust_use_case.TrustReport | None = trust_use_case.inspect(context)
    except PolicyViolation as exc:  # e.g. a hard-denied prefix in the user config
        report = None
        notes.append(f"the execution surface cannot be trusted: {exc.message}")
    return InitResult(
        repo_root=str(root),
        mode=scan.mode,
        detected_stack=detected,
        stack_template=template_name,
        written=written,
        kept=kept,
        notes=tuple(notes),
        warnings=context.warnings,
        trust=report,
    )
