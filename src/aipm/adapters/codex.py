"""Codex CLI adapter: render, context files and dispatch (ARCHITECTURE §11, ADR-0026).

Verified against the Codex CLI docs for 0.167.2 (docs/adapters.md):

- `codex exec … -` reads the prompt from stdin; `--json` prints JSONL events.
- `--sandbox workspace-write` confines writes to the worktree with the network off (Seatbelt on
  macOS, bubblewrap on Linux). Every other mode is forbidden (`command_policy`), and
  `-c approval_policy=never` keeps every command inside the sandbox: nobody is there to approve
  an escalation.
- `CODEX_HOME` relocates Codex's state to the task's own config home, created empty, so no user
  `config.toml`, `AGENTS.md`, skills, rules or hooks apply, and the repository's `.codex/` is
  read only for a trusted project, which an empty home trusts none of. `--ignore-rules` skips
  execpolicy rules as well.
- `CODEX_API_KEY` is the key a non-interactive run reads.

Codex has no per-command allowlist for its shell: the sandbox stands in for one, and aipm runs
the gates itself. It reports no cost, so the build loop charges each attempt its task budget.
A fix attempt is a new `exec` with the fix prompt.
"""

from aipm.adapters._common import (
    Detector,
    DetectSpec,
    HeadlessAdapter,
    blocked_question,
    final_text,
    json_lines,
)
from aipm.adapters.base import AgentResult, ConfigHomeSpec, DispatchLimits
from aipm.context import generator
from aipm.domain.models import GeneratedFile, ProjectContext, ToolName, Workspace
from aipm.execution.process import ProcessResult

API_DOMAINS: tuple[str, ...] = ("api.openai.com",)
"""The `api-only` network profile; not documented by OpenAI, so a wrong guess fails closed."""
REQUIRED_ENV: tuple[str, ...] = ("CODEX_API_KEY",)
CONFIG_HOME = ConfigHomeSpec(
    env_var="CODEX_HOME",
    protected=(
        "config.toml",
        "AGENTS.md",
        "AGENTS.override.md",
        "skills",
        "rules",
        "hooks",
        "hooks.json",
        "prompts",
    ),
)
"""What Codex would read as user settings, instructions, skills, rules or hooks."""
DETECT = DetectSpec(
    tool=ToolName.CODEX,
    program="codex",
    help_args=("exec", "--help"),
    flags=("--sandbox", "--json", "--ephemeral", "--ignore-rules", "--config"),
    words=("workspace-write",),
    hint="Install Codex CLI, or run tasks yourself with `aipm prompt` and `aipm verify`.",
)
FIXED: tuple[str, ...] = (
    "exec", "--sandbox", "workspace-write", "--json", "--ephemeral", "--ignore-rules",
    "-c", "approval_policy=never",
    "-c", "analytics.enabled=false",
    "-c", "check_for_update_on_startup=false",
)  # fmt: skip
DETECTOR = Detector(DETECT)


class CodexAdapter(HeadlessAdapter):
    """The Codex CLI adapter."""

    name: ToolName = ToolName.CODEX
    required_env: tuple[str, ...] = REQUIRED_ENV
    api_domains: tuple[str, ...] = API_DOMAINS
    config_home: ConfigHomeSpec = CONFIG_HOME
    detector: Detector = DETECTOR

    def context_files(self, ctx: ProjectContext) -> list[GeneratedFile]:
        """`AGENTS.md` (native for Codex) and aipm's skills under `.agents/skills/`."""
        return [generator.agents_md(ctx), *generator.codex_skills(ctx)]

    def _argv(self, limits: DispatchLimits, ws: Workspace, prompt_file: object) -> list[str]:
        del limits, ws, prompt_file  # the sandbox, not an allowlist, bounds the shell
        return [*self._launcher(), *FIXED, "-"]

    def parse_result(self, out: ProcessResult) -> AgentResult:
        """The last `agent_message` and whether the last turn completed. Self-reports carry no
        authority: only the `AIPM-BLOCKED:` line is read from the message."""
        message: str | None = None
        saw = False
        failed = False
        for event in json_lines(out.stdout):
            kind = event.get("type")
            if kind == "item.completed":
                item = event.get("item")
                if isinstance(item, dict) and item.get("type") == "agent_message":  # pyright: ignore[reportUnknownMemberType]
                    message = final_text(item.get("text"))  # pyright: ignore[reportUnknownMemberType, reportUnknownArgumentType]
            elif kind == "turn.completed":
                saw, failed = True, False
            elif kind in ("turn.failed", "error"):
                saw, failed = True, True
        return AgentResult(
            exit_code=out.returncode,
            timed_out=out.timed_out,
            saw_result=saw,
            is_error=failed,
            subtype=("error" if failed else "success") if saw else None,
            blocked_question=blocked_question(message or ""),
        )


def create() -> CodexAdapter:
    """Return the adapter."""
    return CodexAdapter()
