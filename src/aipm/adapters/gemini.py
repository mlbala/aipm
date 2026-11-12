"""Gemini CLI adapter: render, context files and dispatch (ARCHITECTURE §11, ADR-0026).

Verified against the Gemini CLI docs for 0.68.0 (docs/adapters.md):

- Piped stdin is the prompt and `-p` is appended to it; `--output-format json` prints one
  object with `response`, `stats` and `error`.
- `--approval-mode auto_edit` approves file edits only. `--allowed-tools
  run_shell_command(<gate prefix>)` allows each gate by prefix; Gemini splits `&&`, `||` and `;`
  chains and checks each part, and in a headless run any other shell call is denied. The flag
  is deprecated in favour of the policy engine but still listed; detection fails closed when
  it goes.
- `GEMINI_CLI_HOME` relocates `~/.gemini` to the task's own config home, where aipm writes the
  only `settings.json` (usage statistics and auto-update off, `context.fileName` reading
  `AGENTS.md`). `--extensions none` loads no extension.
- Gemini loads a workspace `.gemini/settings.json` (MCP servers, hooks, tool discovery commands,
  wider tool rules) and `.env` files whenever folder trust is off, and with folder trust on a
  headless run of an untrusted folder exits. So a worktree whose root holds `.gemini/` or a
  `.env*` file is refused (exit 6); both are protected paths, which an agent cannot add.
- `--sandbox` (Seatbelt or a container) is used only when `srt` is not: SECURITY.md §9.1 makes
  the tool's sandbox the fallback.

Gemini reports tokens, not cost, so the build loop charges each attempt its task budget.
"""

import json
import os
import stat
from pathlib import Path

from aipm.adapters._common import (
    MAX_OUTPUT_LINE,
    Detector,
    DetectSpec,
    HeadlessAdapter,
    blocked_question,
    check_rule_words,
    final_text,
    json_lines,
)
from aipm.adapters.base import AgentResult, ConfigHomeSpec, DispatchLimits
from aipm.context import generator
from aipm.domain.errors import PolicyViolation
from aipm.domain.models import GeneratedFile, ProjectContext, ToolName, Workspace
from aipm.execution.process import ProcessResult

API_DOMAINS: tuple[str, ...] = ("generativelanguage.googleapis.com",)
"""The `api-only` network profile; not documented by Google, so a wrong guess fails closed."""
REQUIRED_ENV: tuple[str, ...] = ("GEMINI_API_KEY",)
SETTINGS: dict[str, object] = {
    "context": {"fileName": ["AGENTS.md", "GEMINI.md"]},
    "general": {"enableAutoUpdate": False},
    "privacy": {"usageStatisticsEnabled": False},
}
"""The user settings a dispatched Gemini reads: documented keys only."""
SETTINGS_FILE = ".gemini/settings.json"
CONFIG_HOME = ConfigHomeSpec(
    env_var="GEMINI_CLI_HOME",
    protected=(
        SETTINGS_FILE,
        ".gemini/GEMINI.md",
        ".gemini/AGENTS.md",
        ".gemini/.env",
        ".gemini/commands",
        ".gemini/extensions",
        ".gemini/policies",
        ".gemini/agents",
        ".gemini/skills",
        ".gemini/hooks",
        ".gemini/trustedFolders.json",
        ".env",
    ),
    seed=((SETTINGS_FILE, json.dumps(SETTINGS, indent=2, sort_keys=True) + "\n"),),
)
DETECT = DetectSpec(
    tool=ToolName.GEMINI,
    program="gemini",
    help_args=("--help",),
    flags=(
        "--prompt",
        "--approval-mode",
        "--allowed-tools",
        "--output-format",
        "--extensions",
        "--sandbox",
    ),
    words=("auto_edit",),
    hint="Install Gemini CLI, or run tasks yourself with `aipm prompt` and `aipm verify`.",
)
PROMPT_TAIL = "Do the task above, following its rules."
"""What `-p` appends to the prompt on stdin: fixed text."""
DETECTOR = Detector(DETECT)


def env_guard(directory: Path) -> None:
    """An empty, read-only `.env` in `directory`, so Gemini's search for one, which walks up
    from its working directory, ends there and never loads the user's `~/.env` or
    `~/.gemini/.env` (security review of step 08). An existing one must be an empty regular
    file, or dispatch is refused (exit 6)."""
    guard = directory / ".env"
    try:
        fd = os.open(guard, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o400)
    except FileExistsError:
        info = guard.lstat()
        if not stat.S_ISREG(info.st_mode) or info.st_size:
            raise PolicyViolation(
                f"{guard} is not the empty file aipm leaves there for Gemini CLI",
                hint="Remove it; aipm writes it again before the next dispatch.",
            ) from None
        return
    os.close(fd)


def shell_rules(commands: tuple[tuple[str, ...], ...]) -> list[str]:
    """`run_shell_command(<prefix>)` for each gate prefix, in plain words only (exit 6)."""
    rules: list[str] = []
    for argv in commands:
        if argv:
            rule = f"run_shell_command({check_rule_words(argv)})"
            if rule not in rules:
                rules.append(rule)
    return rules


class GeminiAdapter(HeadlessAdapter):
    """The Gemini CLI adapter."""

    name: ToolName = ToolName.GEMINI
    required_env: tuple[str, ...] = REQUIRED_ENV
    api_domains: tuple[str, ...] = API_DOMAINS
    config_home: ConfigHomeSpec = CONFIG_HOME
    detector: Detector = DETECTOR
    agent_env: tuple[tuple[str, str], ...] = (("GEMINI_SANDBOX", "false"),)
    """Set, so no `.env` file can turn a sandbox setting on or off; `--sandbox` still wins."""

    def context_files(self, ctx: ProjectContext) -> list[GeneratedFile]:
        """`AGENTS.md` and `GEMINI.md`, which points to it."""
        return [generator.agents_md(ctx), generator.gemini_md(ctx)]

    def _argv(self, limits: DispatchLimits, ws: Workspace, prompt_file: Path) -> list[str]:
        del ws, prompt_file
        argv = [
            *self._launcher(), "--approval-mode", "auto_edit", "--output-format", "json",
            "--extensions", "none",
        ]  # fmt: skip
        for rule in shell_rules(limits.allowed_commands):
            argv += ["--allowed-tools", rule]
        if limits.native_sandbox:
            argv.append("--sandbox")
        return [*argv, "--prompt", PROMPT_TAIL]

    def _check_workspace(self, ws: Workspace) -> None:
        """Refuse a worktree whose root holds `.gemini/` or a `.env*` file in any case (macOS
        file systems ignore case), exit 6; then stop Gemini's upward `.env` search at the
        worktree's parent, which aipm owns, before it reaches the user's home."""
        try:
            names = [entry.name for entry in os.scandir(ws.root)]
        except FileNotFoundError:
            return
        found = sorted(
            n for n in names if n.casefold() == ".gemini" or n.casefold().startswith(".env")
        )
        if found:
            raise PolicyViolation(
                f"the worktree holds {', '.join(found)}, which Gemini CLI would load as settings "
                "or environment",
                hint="Remove them from the repository, or dispatch with another tool.",
            )
        env_guard(ws.root.parent)

    def parse_result(self, out: ProcessResult) -> AgentResult:
        """`response` and `error` from the JSON result. Self-reports carry no authority: only
        the `AIPM-BLOCKED:` line is read from the response."""
        base = AgentResult(exit_code=out.returncode, timed_out=out.timed_out)
        doc = _result_doc(out.stdout)
        if doc is None:
            return base
        failed = doc.get("error") is not None
        return AgentResult(
            exit_code=out.returncode,
            timed_out=out.timed_out,
            saw_result=True,
            is_error=failed,
            subtype="error" if failed else "success",
            blocked_question=blocked_question(final_text(doc.get("response"))),
        )


def _result_doc(stdout: bytes) -> dict[str, object] | None:
    """The JSON result: the whole output, or its last object line that has one of its keys."""
    text = stdout.strip()
    if text.startswith(b"{") and len(text) <= MAX_OUTPUT_LINE:
        try:
            data: object = json.loads(text)
        except ValueError:
            data = None
        if isinstance(data, dict):
            return data  # pyright: ignore[reportUnknownVariableType]
    found = [d for d in json_lines(stdout) if "response" in d or "error" in d]
    return found[-1] if found else None


def create() -> GeminiAdapter:
    """Return the adapter."""
    return GeminiAdapter()
