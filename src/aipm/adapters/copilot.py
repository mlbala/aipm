"""GitHub Copilot CLI adapter: render and context files; dispatch disabled (ADR-0025).

Checked against the Copilot CLI docs for 1.0.109 (docs/adapters.md). Two safety cells are not
documented, so the adapter ships render-only: `detect` always lists them as missing, and
`build`/`run --tool copilot` exits 8 and suggests `aipm prompt`.

- How `--allow-tool 'shell(<cmd>)'` matches: the docs call `shell(npm test)` "the exact
  command" and `shell(git:*)` every subcommand, but say nothing of arguments after a prefix or
  of `&&` chains, so a gate rule may allow more than the gate.
- How a markdown prompt is delivered: piped stdin is ignored with `-p`, and `--attachment`
  takes images and PDFs.

`build_invocation` is complete, so the contract suite covers it and enabling dispatch is one
constant plus an ADR: a fixed `-p` that names the prompt file in the attempt's context
directory (`--add-dir`, which the sandbox lets the agent read but not write), `--allow-tool
write` and one `shell(<gate prefix>)` per gate, `--no-ask-user`, `--secret-env-vars`, JSON
output, no auto-update, no built-in MCP servers, and `COPILOT_HOME` set to the task's empty
config home, which trusts no folder, so the repository's hooks and MCP servers do not load.
"""

from pathlib import Path

from aipm.adapters._common import Detector, DetectSpec, HeadlessAdapter, check_rule_words
from aipm.adapters.base import AgentResult, ConfigHomeSpec, DispatchLimits, RenderedTaskPrompt
from aipm.context import generator
from aipm.domain.models import GeneratedFile, ProjectContext, ToolName, Workspace
from aipm.execution.process import ProcessResult

API_DOMAINS: tuple[str, ...] = (
    "api.githubcopilot.com", "api.individual.githubcopilot.com",
    "api.business.githubcopilot.com", "api.enterprise.githubcopilot.com", "api.github.com",
)  # fmt: skip
"""The `api-only` network profile; not documented by GitHub, so a wrong guess fails closed."""
REQUIRED_ENV: tuple[str, ...] = ("COPILOT_GITHUB_TOKEN",)
CONFIG_HOME = ConfigHomeSpec(
    env_var="COPILOT_HOME",
    protected=(
        "config.json",
        "settings.json",
        "mcp-config.json",
        "lsp-config.json",
        "permissions-config.json",
        "providers.json",
        "hooks",
        "agents",
        "skills",
        "extensions",
        "instructions",
        "copilot-instructions.md",
    ),
)
UNVERIFIED: tuple[str, ...] = (
    "unverified: how shell permission rules match",
    "unverified: markdown prompt delivery",
)
"""Safety cells the docs leave open (ADR-0025). While this is not empty, Copilot is
render-only."""
DETECT = DetectSpec(
    tool=ToolName.COPILOT,
    program="copilot",
    help_args=("--help",),
    flags=(
        "--prompt",
        "--allow-tool",
        "--no-ask-user",
        "--secret-env-vars",
        "--output-format",
        "--add-dir",
        "--no-auto-update",
        "--disable-builtin-mcps",
    ),
    unverified=UNVERIFIED,
    hint="Copilot CLI is render-only in aipm: run tasks yourself with `aipm prompt`.",
)
DETECTOR = Detector(DETECT)


class CopilotAdapter(HeadlessAdapter):
    """The Copilot CLI adapter (render-only)."""

    name: ToolName = ToolName.COPILOT
    required_env: tuple[str, ...] = REQUIRED_ENV
    api_domains: tuple[str, ...] = API_DOMAINS
    config_home: ConfigHomeSpec = CONFIG_HOME
    detector: Detector = DETECTOR

    def context_files(self, ctx: ProjectContext) -> list[GeneratedFile]:
        """`AGENTS.md` (native for Copilot) and a thin `.github/copilot-instructions.md`."""
        return [generator.agents_md(ctx), generator.copilot_instructions(ctx)]

    def _argv(self, limits: DispatchLimits, ws: Workspace, prompt_file: Path) -> list[str]:
        argv = [
            *self._launcher(),
            "-p", f"Read {prompt_file} and do the task it describes, following its rules.",
            "--add-dir", str(ws.context_dir),
            "--output-format", "json", "--no-ask-user", "--no-auto-update",
            "--disable-builtin-mcps", "--secret-env-vars", ",".join(REQUIRED_ENV),
            "--allow-tool", "write",
        ]  # fmt: skip
        seen: set[str] = set()
        for command in limits.allowed_commands:
            if command and (rule := f"shell({check_rule_words(command)})") not in seen:
                seen.add(rule)
                argv += ["--allow-tool", rule]
        return argv

    def _stdin(self, p: RenderedTaskPrompt) -> bytes:
        del p
        return b""

    def _files(self, p: RenderedTaskPrompt, prompt_file: Path) -> tuple[tuple[Path, str], ...]:
        return ((prompt_file, p.text),)

    def parse_result(self, out: ProcessResult) -> AgentResult:
        """The exit status only: the JSON event schema is not documented, so no blocker
        question is read (ADR-0025)."""
        return AgentResult(exit_code=out.returncode, timed_out=out.timed_out)


def create() -> CopilotAdapter:
    """Return the adapter."""
    return CopilotAdapter()
