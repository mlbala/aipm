"""Claude Code adapter: render in v0.1, dispatch in v0.3 (ARCHITECTURE §11).

- `context_files`: `AGENTS.md`, `CLAUDE.md` importing it with `@AGENTS.md` (the pattern the
  Claude Code memory docs give for sharing one file with other tools), and from v0.2 the
  subagents `.claude/agents/aipm-{test-writer,reviewer}.md` and the skills
  `.claude/skills/aipm-{task-protocol,run-checks}/SKILL.md`.
- `render_prompt`: the task prompt from `templates/claude_code/task.md.j2`. Every model-written
  field is inside an `untrusted` block with a fresh nonce; IDs, globs and gate argv are in code
  spans; protected paths appear only as "MUST NOT modify" rules. The result is checked against
  invariant I-3 and for well-formed blocks before it is returned.
- `detect`: `claude --version` through `run_safe`, cached per executable path for the process.
"""

import os
import re
import shutil
import tempfile
from collections.abc import Callable
from pathlib import Path
from typing import cast

from aipm import adapters as _package
from aipm.adapters.base import (
    AgentResult,
    Capabilities,
    DispatchLimits,
    Invocation,
    RenderedTaskPrompt,
)
from aipm.context import generator
from aipm.context.markdown import agent_text_problems, code_span, fence
from aipm.domain.errors import AipmError, PolicyViolation
from aipm.domain.models import GeneratedFile, ProjectContext, TaskSpec, ToolName, Workspace
from aipm.execution.process import ProcessResult, build_env, run_safe
from aipm.security.untrusted import (
    NonceFactory,
    PackageTemplateLoader,
    Untrusted,
    check_blocks,
    make_env,
)

DETECT_TIMEOUT_S = 10.0
_VERSION = re.compile(r"\b(\d+\.\d+\.\d+)\b")
_BLANK_RUNS = re.compile(r"\n{3,}")
_detected: dict[str, Capabilities] = {}


def _detect(which: Callable[[str], str | None]) -> Capabilities:
    found = which("claude")
    if found is None:
        return Capabilities(ToolName.CLAUDE, found=False)
    path = os.path.realpath(found)
    cached = _detected.get(path)
    if cached is not None:
        return cached
    try:
        with tempfile.TemporaryDirectory(prefix="aipm-detect-") as scratch:
            result = run_safe(
                [path, "--version"],
                cwd=Path(scratch),
                env=build_env(),
                timeout_s=DETECT_TIMEOUT_S,
                max_output_bytes=4096,
            )
    except (AipmError, OSError):
        return Capabilities(ToolName.CLAUDE, found=True, path=path)
    lines = result.stdout.decode("utf-8", errors="replace").splitlines()
    match = _VERSION.search(lines[0]) if result.returncode == 0 and lines else None
    caps = Capabilities(ToolName.CLAUDE, True, path, match.group(1) if match else None)
    _detected[path] = caps
    return caps


def _dependency_rule(spec: TaskSpec) -> str:
    if spec.new_dependencies == "deny" or not spec.deps_add:
        return "MUST NOT add any dependency."
    declared = ", ".join(f"{eco} {code_span(name)}" for eco, name in spec.deps_add)
    return f"MUST NOT add a dependency other than the ones this task declares: {declared}."


def _view(spec: TaskSpec, ctx: ProjectContext) -> dict[str, object]:
    allowed = ctx.allowed_url_domains

    def spans(values: tuple[str, ...], what: str) -> list[str]:
        return [code_span(generator.path_literal(v, what=what)) for v in values]

    titles = [u for u in spec.upstream if u.title is not None]
    upstream_text = (
        Untrusted(
            generator.clean(
                "\n".join(f"- {u.id}: {u.title.text}" for u in titles if u.title is not None),
                allowed,
            ),
            source=f"{spec.approval}:tasks.yaml#upstream",
        )
        if titles
        else None
    )
    return {
        "id": spec.id,
        "project": code_span(generator.literal(spec.project, allowed, what="the project name")),
        "type": spec.type,
        "size": spec.size,
        "text": spec.text,
        "approved": spec.approval == "approved",
        "approval": spec.approval,
        "acceptance_ids": list(spec.acceptance_ids),
        "upstream": [
            {
                "id": u.id,
                "status": u.status,
                "commit": None if u.commit is None else code_span(u.commit[:12]),
            }
            for u in spec.upstream
        ],
        "upstream_text": upstream_text,
        "owns": spans(spec.owns_files, f"a path {spec.id} owns"),
        "reads": spans(spec.reads_files, f"a path {spec.id} reads"),
        "verify": [
            {"name": g.name, "required": g.required, "command": generator.command_line(g, allowed)}
            for g in spec.verify
        ],
        "builtins": [
            {
                "name": g.name,
                "what": generator.BUILTIN_CHECKS.get(g.builtin or "", "a built-in check"),
            }
            for g in spec.builtin_gates
        ],
        "protected": spans(spec.protected_paths, "a protected path"),
        "dependency_rule": _dependency_rule(spec),
        "network_rule": generator.NETWORK_RULES.get(
            spec.agent_network, generator.NETWORK_RULES["none"]
        ),
        "fix": spec.fix,
        "previous": [
            {"gate": f.gate, "status": f.status, "output": f.output} for f in spec.previous_attempt
        ],
        "omitted": list(spec.omitted),
    }


class ClaudeCodeAdapter:
    """The Claude Code adapter. `nonce` and `which` are seams for tests."""

    name: ToolName = ToolName.CLAUDE

    def __init__(
        self,
        *,
        nonce: NonceFactory | None = None,
        which: Callable[[str], str | None] = shutil.which,
    ) -> None:
        self._nonce = nonce
        self._which = which

    def detect(self) -> Capabilities:
        """`claude --version`, run once per executable path."""
        return _detect(self._which)

    def context_files(self, ctx: ProjectContext) -> list[GeneratedFile]:
        """`AGENTS.md`, `CLAUDE.md`, and aipm's Claude subagents and skills (v0.2)."""
        return [*generator.generate(ctx), *generator.claude_extras(ctx)]

    def render_prompt(self, task: TaskSpec, ctx: ProjectContext) -> RenderedTaskPrompt:
        """Render the task prompt and check it before anyone sees it."""
        loader = PackageTemplateLoader(_package, "templates/claude_code")
        env = make_env(loader) if self._nonce is None else make_env(loader, nonce=self._nonce)
        filters = cast("dict[str, Callable[..., object]]", env.filters)  # pyright: ignore[reportUnknownMemberType]
        filters["fence"] = fence
        text = env.get_template("task.md.j2").render(**_view(task, ctx))
        text = _BLANK_RUNS.sub("\n\n", text).strip("\n") + "\n"
        check_blocks(text)
        problems = agent_text_problems(text, allowed_url_domains=ctx.allowed_url_domains)
        if problems:
            raise PolicyViolation(
                f"the prompt for {task.id} fails invariant I-3: {'; '.join(problems)}",
                hint="This is a bug in aipm; nothing was written. Please report it.",
            )
        return RenderedTaskPrompt(ToolName.CLAUDE, task.id, text, task.omitted)

    def build_invocation(
        self, p: RenderedTaskPrompt, limits: DispatchLimits, ws: Workspace
    ) -> Invocation:
        """Dispatch arrives in v0.3."""
        raise NotImplementedError("v0.3")

    def parse_result(self, out: ProcessResult) -> AgentResult:
        """Dispatch arrives in v0.3."""
        raise NotImplementedError("v0.3")


def create() -> ClaudeCodeAdapter:
    """Return the adapter."""
    return ClaudeCodeAdapter()
