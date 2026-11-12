"""What every coding-agent adapter shares (ARCHITECTURE §10.1, §11; SECURITY.md §7.8, §9).

- The task prompt: one template for every tool (`templates/claude_code/task.md.j2`, which has
  no tool-specific text). Every model-written field is inside an `untrusted` block with a fresh
  nonce; the result is checked against invariant I-3 and for well-formed blocks.
- `blocked_question`: the last `AIPM-BLOCKED:` line, cleaned and capped. Nothing else an agent
  says carries any authority.
- `check_rule_words`: a gate command allowed to an agent's shell tool must be written in plain
  words that a permission rule matches literally and a shell reads as themselves.
- `Detector`: `<tool> --version` and the tool's help, run once per executable and cached; every
  flag dispatch needs must be listed, or dispatch fails closed (exit 8).
- `HeadlessAdapter`: the parts of `ToolAdapter` that Codex, Copilot and Gemini share; each
  subclass supplies its argv, its environment and how to read its output.
"""

import json
import os
import re
import shutil
import tempfile
from collections.abc import Callable, Iterator, Sequence
from dataclasses import dataclass, replace
from pathlib import Path
from typing import cast

from aipm import adapters as _package
from aipm.adapters.base import (
    AgentResult,
    Capabilities,
    ConfigHomeSpec,
    DispatchLimits,
    Invocation,
    RenderedTaskPrompt,
)
from aipm.context import generator
from aipm.context.markdown import agent_text_problems, code_span, fence
from aipm.domain.errors import AipmError, MissingCapability, PolicyViolation, UsageError
from aipm.domain.models import GeneratedFile, ProjectContext, TaskSpec, ToolName, Workspace
from aipm.execution.process import (
    BASE_ENV_ALLOWLIST,
    PROXY_ENV,
    ProcessResult,
    build_env,
    is_inside,
    run_safe,
)
from aipm.execution.sandbox import launcher_for, which_outside
from aipm.execution.worktree import WORKTREES_DIR, cache_root
from aipm.security.command_policy import check_forbidden_flags
from aipm.security.sanitize import sanitize_text
from aipm.security.untrusted import (
    NonceFactory,
    PackageTemplateLoader,
    Untrusted,
    check_blocks,
    make_env,
)

BLOCKED_MARK = "AIPM-BLOCKED:"
MAX_QUESTION = 300
MAX_PROMPT_BYTES = 1_048_576
"""The largest prompt aipm hands a tool other than Claude Code (prompts are capped at 24 KiB)."""
MAX_OUTPUT_LINE = 4 * 1_048_576
MAX_FINAL_TEXT = 65_536
DETECT_TIMEOUT_S = 10.0
HELP_TIMEOUT_S = 15.0
MAX_HELP_BYTES = 262_144
_VERSION = re.compile(r"\b(\d+\.\d+\.\d+)\b")
_BLANK_RUNS = re.compile(r"\n{3,}")
_HELP_FLAG = re.compile(r"--[A-Za-z][A-Za-z-]*")
_RULE_WORD = re.compile(r"[A-Za-z0-9._/@:+=-]+")


def blocked_question(text: str) -> str | None:
    """The question of the last `AIPM-BLOCKED: <q>` line: sanitized, on one line, capped at
    300 characters (SECURITY.md §7.8). `None` when there is none, or it is empty."""
    for line in reversed(text.splitlines()):
        stripped = line.strip()
        if stripped.startswith(BLOCKED_MARK):
            raw = stripped.removeprefix(BLOCKED_MARK)
            question = " ".join(sanitize_text(raw, source="agent output").text.split())
            return question[:MAX_QUESTION] or None
    return None


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


def render_task_prompt(
    tool: ToolName, task: TaskSpec, ctx: ProjectContext, *, nonce: NonceFactory | None = None
) -> RenderedTaskPrompt:
    """Render the task prompt for `tool` and check it before anyone sees it."""
    loader = PackageTemplateLoader(_package, "templates/claude_code")
    env = make_env(loader) if nonce is None else make_env(loader, nonce=nonce)
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
    return RenderedTaskPrompt(tool, task.id, text, task.omitted)


def check_rule_words(argv: Sequence[str]) -> str:
    """`argv` joined with spaces, if every word is one a permission rule matches literally and
    a shell reads as itself (`[A-Za-z0-9._/@:+=-]`); exit 6 otherwise: the rule must allow
    exactly the command the prompt shows."""
    for word in argv:
        if not _RULE_WORD.fullmatch(word):
            raise PolicyViolation(
                f"the gate command word {word[:80]!r} cannot be allowed for a dispatched "
                "agent as written",
                hint="Use plain words (letters, digits, . _ / @ : + = -) in gate commands.",
            )
    return " ".join(argv)


def json_lines(stdout: bytes) -> Iterator[dict[str, object]]:
    """Every line of `stdout` that is a JSON object, skipping overlong and broken lines."""
    for raw in stdout.splitlines():
        if len(raw) > MAX_OUTPUT_LINE or not raw.lstrip().startswith(b"{"):
            continue
        try:
            data: object = json.loads(raw)
        except ValueError:
            continue
        if isinstance(data, dict):
            yield cast("dict[str, object]", data)


def final_text(value: object) -> str:
    """A final message as text, its end kept when it is long (the blocker line is last)."""
    return value[-MAX_FINAL_TEXT:] if isinstance(value, str) else ""


# ---------------------------------------------------------------- detection


@dataclass(frozen=True, slots=True)
class DetectSpec:
    """How to check one tool before dispatch.

    `help_args` print the help that must list `flags`; each of `words` (a choice such as
    `workspace-write`) must appear in it too. `unverified` names safety cells the vendor docs
    leave open: while it is not empty, the tool is never dispatchable (render-only, ADR-0025).
    """

    tool: ToolName
    program: str
    help_args: tuple[str, ...]
    flags: tuple[str, ...]
    words: tuple[str, ...] = ()
    unverified: tuple[str, ...] = ()
    hint: str = "Install it, or run tasks yourself with `aipm prompt` and `aipm verify`."


class Detector:
    """`<tool> --version` and its help, once per executable and launcher, cached."""

    def __init__(self, spec: DetectSpec) -> None:
        self.spec = spec
        self._cache: dict[str, Capabilities] = {}

    def clear(self) -> None:
        """Forget what was detected (tests)."""
        self._cache.clear()

    def detect(
        self, which: Callable[[str], str | None], *, flags: bool, repo: Path | None
    ) -> Capabilities:
        spec = self.spec
        found = which(spec.program)
        if found is None:
            return Capabilities(spec.tool, found=False)
        path = os.path.realpath(found)
        worktrees = (cache_root() / WORKTREES_DIR,)
        launcher = (
            (path,)
            if repo is None
            else launcher_for(path, repo, name=spec.program, hint=spec.hint, also=worktrees)
        )
        key = "\0".join((path, *launcher))
        caps = self._cache.get(key) or self._version(key, path, launcher)
        if flags and caps.version is not None and not caps.flags_checked:
            caps = self._flags(key, caps)
        return caps

    def _run(self, argv: Sequence[str], timeout_s: float, cap: int) -> ProcessResult | None:
        try:
            with tempfile.TemporaryDirectory(prefix="aipm-detect-") as scratch:
                return run_safe(
                    list(argv),
                    cwd=Path(scratch),
                    env=build_env(),
                    timeout_s=timeout_s,
                    max_output_bytes=cap,
                )
        except (AipmError, OSError):
            return None

    def _version(self, key: str, path: str, launcher: tuple[str, ...]) -> Capabilities:
        result = self._run([*launcher, "--version"], DETECT_TIMEOUT_S, 4096)
        if result is None:
            return Capabilities(self.spec.tool, found=True, path=path, launcher=launcher)
        lines = result.stdout.decode("utf-8", errors="replace").splitlines()
        match = _VERSION.search(lines[0]) if result.returncode == 0 and lines else None
        version = match.group(1) if match else None
        caps = Capabilities(self.spec.tool, True, path, version, launcher=launcher)
        self._cache[key] = caps
        return caps

    def _flags(self, key: str, caps: Capabilities) -> Capabilities:
        spec = self.spec
        launcher = caps.launcher or (cast("str", caps.path),)
        result = self._run([*launcher, *spec.help_args], HELP_TIMEOUT_S, MAX_HELP_BYTES)
        readable = (
            result is not None
            and result.returncode == 0
            and not result.timed_out
            and not result.truncated
        )
        text = "" if result is None or not readable else result.stdout.decode("utf-8", "replace")
        missing = self.missing(text) if text else (" ".join(spec.help_args),)
        checked = replace(caps, flags_checked=True, missing=(*missing, *spec.unverified))
        self._cache[key] = checked
        return checked

    def missing(self, text: str) -> tuple[str, ...]:
        """The required flags and words a help text does not list."""
        present = set(_HELP_FLAG.findall(text))
        out = [flag for flag in self.spec.flags if flag not in present]
        out += [word for word in self.spec.words if word not in text]
        return tuple(out)


def lookup(which: Callable[[str], str | None], repo: Path | None) -> Callable[[str], str | None]:
    """`which`, or with `repo` a lookup that skips the repository and aipm's task worktrees,
    so a planted `.venv/bin/<tool>` is never run."""
    if repo is None:
        return which
    worktrees = cache_root() / WORKTREES_DIR

    def outside(name: str) -> str | None:
        if which is shutil.which:
            return which_outside(name, repo, also=(worktrees,))
        found = which(name)
        inside = found is not None and any(is_inside(found, r) for r in (repo, worktrees))
        return None if found is None or inside else found

    return outside


# ---------------------------------------------------------------- the shared adapter


class HeadlessAdapter:
    """The parts of `ToolAdapter` that Codex, Copilot and Gemini share.

    A subclass sets the class attributes and implements `_argv`, `_extra_env`, `_files` and
    `parse_result`. `nonce` and `which` are seams for tests.
    """

    name: ToolName
    required_env: tuple[str, ...]
    api_domains: tuple[str, ...]
    config_home: ConfigHomeSpec
    detector: Detector
    agent_env: tuple[tuple[str, str], ...] = ()
    """Fixed variables that turn off update checks and telemetry."""

    def __init__(
        self,
        *,
        nonce: NonceFactory | None = None,
        which: Callable[[str], str | None] = shutil.which,
    ) -> None:
        self._nonce = nonce
        self._which = which
        self._ready: Capabilities | None = None

    def detect(self, *, flags: bool = False, repo: Path | None = None) -> Capabilities:
        """The version and, with `flags`, the flags dispatch needs; with `repo`, the tool is
        looked up outside the repository only. A dispatchable result is kept for dispatch."""
        caps = self.detector.detect(lookup(self._which, repo), flags=flags, repo=repo)
        if caps.dispatchable:
            self._ready = caps
        return caps

    def context_files(self, ctx: ProjectContext) -> list[GeneratedFile]:
        """`AGENTS.md`, which every tool reads."""
        return [generator.agents_md(ctx)]

    def render_prompt(self, task: TaskSpec, ctx: ProjectContext) -> RenderedTaskPrompt:
        """The shared task prompt, checked before anyone sees it."""
        return render_task_prompt(self.name, task, ctx, nonce=self._nonce)

    def _launcher(self) -> tuple[str, ...]:
        caps = self._ready
        if caps is None or caps.path is None:
            raise MissingCapability(
                f"{self.name.value} has not been checked for the flags dispatch needs",
                hint="This is a bug in aipm: detect(flags=True) must run first.",
            )
        return caps.launcher or (caps.path,)

    def _argv(self, limits: DispatchLimits, ws: Workspace, prompt_file: Path) -> list[str]:
        raise NotImplementedError

    def _extra_env(self, ws: Workspace) -> dict[str, str]:
        return {self.config_home.env_var: str(ws.config_home), "TMPDIR": str(ws.temp_dir)}

    def _stdin(self, p: RenderedTaskPrompt) -> bytes:
        return p.text.encode("utf-8")

    def _files(self, p: RenderedTaskPrompt, prompt_file: Path) -> tuple[tuple[Path, str], ...]:
        del p, prompt_file
        return ()

    def _check_workspace(self, ws: Workspace) -> None:
        """Refuse a worktree the tool would read settings from (exit 6); nothing by default."""
        del ws

    def _final(self, argv: list[str]) -> tuple[str, ...]:
        final = tuple(argv)
        check_forbidden_flags(self.name, final)
        return final

    def preview_argv(self, limits: DispatchLimits, ws: Workspace) -> tuple[str, ...]:
        """The argv a dispatch would use, for `build --dry-run`. Needs no API key."""
        return self._final(self._argv(limits, ws, ws.context_dir / "prompt-<random>.md"))

    def build_invocation(
        self, p: RenderedTaskPrompt, limits: DispatchLimits, ws: Workspace
    ) -> Invocation:
        """The headless invocation for one attempt. Needs `detect(flags=True)`."""
        if len(p.text.encode("utf-8")) > MAX_PROMPT_BYTES:
            raise UsageError(f"the prompt for {p.task_id} is larger than aipm hands an agent")
        self._check_workspace(ws)
        prompt_file = ws.context_dir / f"prompt-{os.urandom(8).hex()}.md"
        argv = self._final(self._argv(limits, ws, prompt_file))
        for name in self.required_env:
            if not os.environ.get(name):
                raise MissingCapability(
                    f"{name} is not set; a dispatched {self.name.value} needs it",
                    hint="Give coding agents a dedicated key with a spend limit, or run the "
                    "task yourself with `aipm prompt`.",
                )
        names = [*BASE_ENV_ALLOWLIST, *PROXY_ENV, *limits.pass_env, *self.required_env]
        extra = {**self._extra_env(ws), **dict(self.agent_env)}
        launcher = self._launcher()
        return Invocation(
            argv=argv,
            stdin=self._stdin(p),
            env=build_env(names, extra=extra),
            files=self._files(p, prompt_file),
            api_domains=self.api_domains,
            programs=tuple(x for x in launcher if x),
        )

    def parse_result(self, out: ProcessResult) -> AgentResult:
        raise NotImplementedError
