"""Claude Code adapter: render in v0.1, dispatch in v0.3 (ARCHITECTURE §11).

- `context_files`: `AGENTS.md`, `CLAUDE.md` importing it with `@AGENTS.md` (the pattern the
  Claude Code memory docs give for sharing one file with other tools), and from v0.2 the
  subagents `.claude/agents/aipm-{test-writer,reviewer}.md` and the skills
  `.claude/skills/aipm-{task-protocol,run-checks}/SKILL.md`.
- `render_prompt`: the task prompt from `templates/claude_code/task.md.j2`. Every model-written
  field is inside an `untrusted` block with a fresh nonce; IDs, globs and gate argv are in code
  spans; protected paths appear only as "MUST NOT modify" rules. The result is checked against
  invariant I-3 and for well-formed blocks before it is returned.
- `detect`: `claude --version` through `run_safe`, cached per executable path for the process;
  for dispatch (`flags=True`) also `claude --help`, once per executable, to confirm every flag
  dispatch relies on (ADR-0023). A missing one fails closed (exit 8).
- `build_invocation` (v0.3): argv from fixed fragments only, `--bare`, `dontAsk` with no
  permission prompts, no repository or local settings and no MCP servers (`--setting-sources
  user --strict-mcp-config`, with an isolated `CLAUDE_CONFIG_DIR`), the allowed tools named one
  by one, the task budget, the project context in a file the agent cannot write, the prompt on
  stdin. `check_forbidden_flags` runs on the final argv.
- `parse_result` (v0.3): the last stream-json `result` event (cost, session, error) and the last
  `AIPM-BLOCKED:` line of the final message. `AIPM-DONE` and any other claim are ignored.
"""

import json
import math
import os
import re
import secrets
import shutil
import tempfile
from collections.abc import Callable, Sequence
from dataclasses import replace
from pathlib import Path
from typing import Annotated, cast

from pydantic import Field, StrictBool, StrictStr, ValidationError

from aipm.adapters._common import (
    BLOCKED_MARK,
    MAX_QUESTION,
    blocked_question,
    check_rule_words,
    render_task_prompt,
)
from aipm.adapters.base import (
    AgentResult,
    Capabilities,
    ConfigHomeSpec,
    DispatchLimits,
    Invocation,
    RenderedTaskPrompt,
)
from aipm.context import generator
from aipm.domain.errors import AipmError, MissingCapability, PolicyViolation, UsageError
from aipm.domain.models import GeneratedFile, ProjectContext, TaskSpec, ToolName, Workspace
from aipm.domain.models.base import StrictModel
from aipm.execution.process import (
    BASE_ENV_ALLOWLIST,
    PROXY_ENV,
    ProcessResult,
    build_env,
    is_inside,
    run_safe,
)
from aipm.execution.sandbox import CONFIG_HOME_PROTECTED, launcher_for, which_outside
from aipm.execution.worktree import WORKTREES_DIR, cache_root
from aipm.security.command_policy import check_forbidden_flags
from aipm.security.untrusted import (
    NonceFactory,
)

DETECT_TIMEOUT_S = 10.0
_HINT = "Install Claude Code, or run tasks yourself with `aipm prompt` and `aipm verify`."
HELP_TIMEOUT_S = 15.0
MAX_HELP_BYTES = 262_144
API_DOMAINS: tuple[str, ...] = ("api.anthropic.com",)
"""The `api-only` network profile of a dispatched Claude Code (SECURITY.md §9.1)."""
REQUIRED_ENV: tuple[str, ...] = ("ANTHROPIC_API_KEY",)
"""Bare mode reads no subscription login: the agent's own API key (SECURITY.md §8)."""
REQUIRED_FLAGS: tuple[str, ...] = (
    "--bare", "--print", "--output-format", "--verbose", "--permission-mode",
    "--permission-prompts", "--allowedTools", "--max-budget-usd", "--append-system-prompt-file",
    "--resume", "--setting-sources", "--strict-mcp-config",
)  # fmt: skip
REQUIRED_CHOICES: tuple[tuple[str, str], ...] = (
    ("--permission-mode", "dontAsk"),
    ("--permission-prompts", "none"),
    ("--output-format", "stream-json"),
)
BASE_TOOLS: tuple[str, ...] = ("Read", "Edit", "Write", "Glob", "Grep")
AGENT_ENV: dict[str, str] = {
    "DISABLE_AUTOUPDATER": "1",
    "CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC": "1",
}
"""No update checks, telemetry or error reports: the network profile allows the API only."""
MAX_PROMPT_STDIN = 10 * 1_048_576
"""Claude Code reads at most 10 MB from stdin."""
MAX_RESULT_LINE = 4 * 1_048_576
MAX_RESULT_TEXT = 65_536
_VERSION = re.compile(r"\b(\d+\.\d+\.\d+)\b")
_HELP_FLAG = re.compile(r"--[A-Za-z][A-Za-z-]*(?:\[-file\])?")
SESSION_ID = re.compile(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}")
_detected: dict[str, Capabilities] = {}
__all__ = [
    "BLOCKED_MARK", "MAX_QUESTION", "ClaudeCodeAdapter", "allowed_tools", "blocked_question",
    "create", "help_flags", "missing_flags",
]  # fmt: skip
CONFIG_HOME = ConfigHomeSpec(
    env_var="CLAUDE_CONFIG_DIR", protected=CONFIG_HOME_PROTECTED, keep=frozenset({"projects"})
)
"""`CLAUDE_CONFIG_DIR` (ADR-0023): the session transcripts under `projects/` stay for
`--resume`; the settings, hooks, agents, skills, commands and plugins are protected."""


def help_flags(text: str) -> frozenset[str]:
    """Every `--flag` named in a help text; `--x[-file]` names both `--x` and `--x-file`."""
    found: set[str] = set()
    for match in _HELP_FLAG.finditer(text):
        token = match.group(0)
        if token.endswith("[-file]"):
            base = token.removesuffix("[-file]")
            found |= {base, f"{base}-file"}
        else:
            found.add(token)
    return frozenset(found)


def missing_flags(text: str) -> tuple[str, ...]:
    """The required flags and choices a `claude --help` text does not list."""
    present = help_flags(text)
    missing = [flag for flag in REQUIRED_FLAGS if flag not in present]
    missing += [
        f"{flag} {choice}" for flag, choice in REQUIRED_CHOICES if f'"{choice}"' not in text
    ]
    return tuple(missing)


def _version(path: str, launcher: tuple[str, ...]) -> Capabilities:
    try:
        with tempfile.TemporaryDirectory(prefix="aipm-detect-") as scratch:
            result = run_safe(
                [*launcher, "--version"],
                cwd=Path(scratch),
                env=build_env(),
                timeout_s=DETECT_TIMEOUT_S,
                max_output_bytes=4096,
            )
    except (AipmError, OSError):
        return Capabilities(ToolName.CLAUDE, found=True, path=path, launcher=launcher)
    lines = result.stdout.decode("utf-8", errors="replace").splitlines()
    match = _VERSION.search(lines[0]) if result.returncode == 0 and lines else None
    version = match.group(1) if match else None
    caps = Capabilities(ToolName.CLAUDE, True, path, version, launcher=launcher)
    _detected[_key(path, launcher)] = caps
    return caps


def _flags(caps: Capabilities) -> Capabilities:
    """`caps`, with the flags `claude --help` lists checked; cached with it."""
    path = cast("str", caps.path)
    launcher = caps.launcher or (path,)
    try:
        with tempfile.TemporaryDirectory(prefix="aipm-detect-") as scratch:
            result = run_safe(
                [*launcher, "--help"],
                cwd=Path(scratch),
                env=build_env(),
                timeout_s=HELP_TIMEOUT_S,
                max_output_bytes=MAX_HELP_BYTES,
            )
    except (AipmError, OSError):
        return replace(caps, flags_checked=True, missing=("--help",))
    readable = result.returncode == 0 and not result.timed_out and not result.truncated
    text = result.stdout.decode("utf-8", errors="replace") if readable else ""
    checked = replace(
        caps, flags_checked=True, missing=missing_flags(text) if text else ("--help",)
    )
    _detected[_key(path, launcher)] = checked
    return checked


def _key(path: str, launcher: tuple[str, ...]) -> str:
    return "\0".join((path, *launcher))


def _detect(
    which: Callable[[str], str | None], *, flags: bool = False, repo: Path | None = None
) -> Capabilities:
    found = which("claude")
    if found is None:
        return Capabilities(ToolName.CLAUDE, found=False)
    path = os.path.realpath(found)
    # An npm-installed `claude` is a `#!/usr/bin/env node` script: with a repository, `node` is
    # resolved outside it and started explicitly, never looked up on PATH (step 07 review).
    worktrees = (cache_root() / WORKTREES_DIR,)
    launcher = (
        (path,)
        if repo is None
        else launcher_for(path, repo, name="claude", hint=_HINT, also=worktrees)
    )
    caps = _detected.get(_key(path, launcher)) or _version(path, launcher)
    if flags and caps.version is not None and not caps.flags_checked:
        caps = _flags(caps)
    return caps


def allowed_tools(commands: Sequence[Sequence[str]]) -> str:
    """`--allowedTools`: the file tools, then `Bash(<p>)` and `Bash(<p> *)` per gate prefix.

    Each word must be one a permission rule matches literally and a shell reads as itself
    (`[A-Za-z0-9._/@:+=-]`), or exit 6: the rule must allow exactly the command the prompt shows.
    """
    rules: list[str] = list(BASE_TOOLS)
    for argv in commands:
        if not argv:
            continue
        line = check_rule_words(argv)
        for rule in (f"Bash({line})", f"Bash({line} *)"):
            if rule not in rules:
                rules.append(rule)
    return ",".join(rules)


def _usd(amount: float) -> str:
    if isinstance(amount, bool) or not math.isfinite(amount) or amount <= 0:
        raise UsageError(f"the task budget must be a positive amount, not {amount!r}")
    return f"{max(amount, 0.01):.2f}"


class _ResultEvent(StrictModel):
    """The fields aipm reads from Claude Code's final stream-json `result` event."""

    type: StrictStr
    subtype: Annotated[StrictStr, Field(pattern=r"^[a-z_]{1,64}$")] | None = None
    is_error: StrictBool = False
    total_cost_usd: (
        Annotated[float, Field(strict=True, ge=0, le=100_000, allow_inf_nan=False)] | None
    ) = None
    session_id: Annotated[StrictStr, Field(pattern=f"^{SESSION_ID.pattern}$")] | None = None
    result: Annotated[StrictStr, Field(max_length=MAX_RESULT_TEXT)] | None = None


_RESULT_KEYS = ("type", "subtype", "is_error", "total_cost_usd", "session_id", "result")


def _total(value: object) -> float | None:
    if isinstance(value, bool) or not isinstance(value, int | float):
        return None
    number = float(value)
    return number if math.isfinite(number) and number >= 0 else None


def _last_result(stdout: bytes) -> _ResultEvent | None:
    """The last `result` event, charged the highest total any `result` event reports.

    Claude Code prints one per `-p` run. A second line (forged after the real one, with a lower
    total) could otherwise have lowered what the run budget counts; now extra lines can only
    raise it (red-team v0.3).
    """
    found: list[dict[str, object]] = []
    for raw in stdout.splitlines():
        if len(raw) > MAX_RESULT_LINE or b'"result"' not in raw:
            continue
        try:
            data: object = json.loads(raw)
        except ValueError:
            continue
        if isinstance(data, dict) and cast("dict[str, object]", data).get("type") == "result":
            found.append(cast("dict[str, object]", data))
    if not found:
        return None
    picked = {k: found[-1][k] for k in _RESULT_KEYS if k in found[-1]}
    totals = [t for t in (_total(f.get("total_cost_usd")) for f in found) if t is not None]
    if _total(picked.get("total_cost_usd")) is not None:
        picked["total_cost_usd"] = max(totals)
    text = picked.get("result")
    if isinstance(text, str) and len(text) > MAX_RESULT_TEXT:
        picked["result"] = text[-MAX_RESULT_TEXT:]  # the blocker line is at the end
    try:
        return _ResultEvent.model_validate(picked)
    except ValidationError:
        return None


class ClaudeCodeAdapter:
    """The Claude Code adapter. `nonce` and `which` are seams for tests."""

    name: ToolName = ToolName.CLAUDE
    required_env: tuple[str, ...] = REQUIRED_ENV
    api_domains: tuple[str, ...] = API_DOMAINS
    config_home: ConfigHomeSpec = CONFIG_HOME

    def __init__(
        self,
        *,
        nonce: NonceFactory | None = None,
        which: Callable[[str], str | None] = shutil.which,
    ) -> None:
        self._nonce = nonce
        self._which = which
        self._ready: Capabilities | None = None

    def _lookup(self, repo: Path | None) -> Callable[[str], str | None]:
        if repo is None:
            return self._which

        worktrees = cache_root() / WORKTREES_DIR

        def outside(name: str) -> str | None:
            if self._which is shutil.which:
                return which_outside(name, repo, also=(worktrees,))
            found = self._which(name)
            inside = found is not None and any(is_inside(found, r) for r in (repo, worktrees))
            return None if found is None or inside else found

        return outside

    def detect(self, *, flags: bool = False, repo: Path | None = None) -> Capabilities:
        """`claude --version`, run once per executable path; with `flags`, `claude --help` too.

        With `repo`, `claude` is looked up on PATH outside the repository only, so a planted
        `.venv/bin/claude` is never run. A dispatchable result is kept for `build_invocation`.
        """
        caps = _detect(self._lookup(repo), flags=flags, repo=repo)
        if caps.dispatchable:
            self._ready = caps
        return caps

    def context_files(self, ctx: ProjectContext) -> list[GeneratedFile]:
        """`AGENTS.md`, `CLAUDE.md`, and aipm's Claude subagents and skills (v0.2)."""
        return [*generator.generate(ctx), *generator.claude_extras(ctx)]

    def render_prompt(self, task: TaskSpec, ctx: ProjectContext) -> RenderedTaskPrompt:
        """Render the task prompt and check it before anyone sees it."""
        return render_task_prompt(ToolName.CLAUDE, task, ctx, nonce=self._nonce)

    def _argv(self, limits: DispatchLimits, ws: Workspace, context_file: Path) -> tuple[str, ...]:
        caps = self._ready
        if caps is None or caps.path is None:
            raise MissingCapability(
                "Claude Code has not been checked for the flags dispatch needs",
                hint="This is a bug in aipm: detect(flags=True) must run first.",
            )
        argv: list[str] = list(caps.launcher or (caps.path,))
        if limits.bare:
            argv.append("--bare")
        argv += [
            "-p", "--output-format", "stream-json", "--verbose",
            "--permission-mode", "dontAsk", "--permission-prompts", "none",
            "--setting-sources", "user", "--strict-mcp-config",
            "--allowedTools", allowed_tools(limits.allowed_commands),
            "--max-budget-usd", _usd(limits.task_usd),
            "--append-system-prompt-file", str(context_file),
        ]  # fmt: skip
        if ws.resume_session is not None:
            if not SESSION_ID.fullmatch(ws.resume_session):
                raise PolicyViolation("the session to resume is not a Claude Code session id")
            argv += ["--resume", ws.resume_session]
        check_forbidden_flags(ToolName.CLAUDE, tuple(argv), allow_auto_mode=limits.allow_auto_mode)
        return tuple(argv)

    def preview_argv(self, limits: DispatchLimits, ws: Workspace) -> tuple[str, ...]:
        """The argv a dispatch would use, for `build --dry-run`; the context file is shown as
        `<context>/agents-<random>.md`. Needs no API key."""
        return self._argv(limits, ws, ws.context_dir / "agents-<random>.md")

    def build_invocation(
        self, p: RenderedTaskPrompt, limits: DispatchLimits, ws: Workspace
    ) -> Invocation:
        """The headless invocation for one attempt (ADR-0023). Needs `detect(flags=True)`."""
        stdin = p.text.encode("utf-8")
        if len(stdin) > MAX_PROMPT_STDIN:
            raise UsageError(f"the prompt for {p.task_id} is larger than Claude Code reads")
        context_file = ws.context_dir / f"agents-{secrets.token_hex(8)}.md"
        argv = self._argv(limits, ws, context_file)
        names = [*BASE_ENV_ALLOWLIST, *PROXY_ENV, *limits.pass_env]
        if limits.bare:
            for name in REQUIRED_ENV:
                if not os.environ.get(name):
                    raise MissingCapability(
                        f"{name} is not set; Claude Code in bare mode needs an API key",
                        hint="Give coding agents a dedicated API key with a spend limit, or run "
                        "the task yourself with `aipm prompt`.",
                    )
            names += REQUIRED_ENV
        extra = {"CLAUDE_CONFIG_DIR": str(ws.config_home), "TMPDIR": str(ws.temp_dir), **AGENT_ENV}
        context = ws.context_text or "Follow the task prompt.\n"
        caps = self._ready
        programs = () if caps is None else tuple(caps.launcher or (caps.path or "",))
        return Invocation(
            argv=tuple(argv),
            stdin=stdin,
            env=build_env(names, extra=extra),
            files=((context_file, context),),
            api_domains=API_DOMAINS,
            programs=tuple(p for p in programs if p),
        )

    def parse_result(self, out: ProcessResult) -> AgentResult:
        """The final `result` event and the last `AIPM-BLOCKED:` line of the final message.

        Agent self-reports carry no authority: `AIPM-DONE` or "all tests pass" change nothing.
        """
        base = AgentResult(exit_code=out.returncode, timed_out=out.timed_out)
        event = _last_result(out.stdout)
        if event is None:
            return base
        return replace(
            base,
            saw_result=True,
            is_error=event.is_error,
            subtype=event.subtype,
            cost_usd=event.total_cost_usd,
            session_id=event.session_id,
            blocked_question=blocked_question(event.result or ""),
        )


def create() -> ClaudeCodeAdapter:
    """Return the adapter."""
    return ClaudeCodeAdapter()
