"""The adapter contract (ARCHITECTURE §11, §20; build prompt 08): every adapter, for every tool.

Each test runs against all four adapters and their stub binaries (`tests/fakes/bin/`):
detection fails closed, the argv is built from fixed fragments with no forbidden flag, the
environment is an allowlist that holds no secret but the tool's own key, the prompt passes
invariant I-3, and the output parser gives agent self-reports no authority. Copilot is
render-only (ADR-0025): its dispatch is turned on here only to check the invocation it would use.
"""

import json
from dataclasses import replace
from pathlib import Path

import pytest

from aipm.adapters import claude_code, codex, copilot, gemini
from aipm.adapters._common import MAX_PROMPT_BYTES, MAX_QUESTION, Detector
from aipm.adapters.base import DispatchLimits, RenderedTaskPrompt, ToolAdapter
from aipm.adapters.compiler import compile_task_spec
from aipm.domain.errors import ExitCode, MissingCapability, PolicyViolation, UsageError
from aipm.domain.models import ToolName, Workspace
from aipm.execution.process import BASE_ENV_ALLOWLIST, PROXY_ENV, ProcessResult
from aipm.security.command_policy import check_forbidden_flags
from tests.conftest import REPO_ROOT
from tests.fakes.project import clinic_context, clinic_task
from tests.fakes.secrets import AGENT_KEYS, FAKE_SECRETS

STUB_BIN = REPO_ROOT / "tests" / "fakes" / "bin"
UNIT = ("uv", "run", "--frozen", "--offline", "pytest")
LINT = ("uv", "run", "--frozen", "--offline", "ruff", "check")
MODULES: dict[str, object] = {
    "claude": claude_code,
    "codex": codex,
    "copilot": copilot,
    "gemini": gemini,
}
TOOLS = sorted(MODULES)
REQUIRED_FLAGS = {
    "codex": ["--sandbox", "--json", "--ephemeral", "--ignore-rules", "--config"],
    "gemini": ["--approval-mode", "--allowed-tools", "--output-format", "--extensions"],
    "copilot": ["--allow-tool", "--no-ask-user", "--secret-env-vars", "--add-dir"],
    "claude": ["--strict-mcp-config", "--setting-sources", "--permission-prompts"],
}


@pytest.fixture(autouse=True)
def isolated(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    claude_code._detected.clear()  # pyright: ignore[reportPrivateUsage]
    for module in (codex, copilot, gemini):
        module.DETECTOR.clear()
    monkeypatch.setenv("HOME", str(tmp_path / "home"))
    for name, value in FAKE_SECRETS.items():
        monkeypatch.setenv(name, value)
    for name, value in AGENT_KEYS.values():
        monkeypatch.setenv(name, value)


@pytest.fixture
def copilot_on(monkeypatch: pytest.MonkeyPatch) -> None:
    """Copilot with its unverified cells treated as verified, to check its invocation."""
    monkeypatch.setattr(
        copilot.CopilotAdapter, "detector", Detector(replace(copilot.DETECT, unverified=()))
    )


def stub_which(name: str) -> str | None:
    path = STUB_BIN / name
    return str(path) if path.is_file() else None


def _make(tool: str) -> ToolAdapter:
    cls = {
        "claude": claude_code.ClaudeCodeAdapter,
        "codex": codex.CodexAdapter,
        "copilot": copilot.CopilotAdapter,
        "gemini": gemini.GeminiAdapter,
    }[tool]
    return cls(which=stub_which)


def ready(tool: str) -> ToolAdapter:
    adapter = _make(tool)
    caps = adapter.detect(flags=True)
    assert caps.dispatchable, caps.missing
    return adapter


def workspace(tmp_path: Path) -> Workspace:
    dirs = {name: tmp_path / name for name in ("wt", "tmp", "ctx", "cfg")}
    for path in dirs.values():
        path.mkdir(exist_ok=True)
    return Workspace(
        root=dirs["wt"], temp_dir=dirs["tmp"], context_dir=dirs["ctx"], config_home=dirs["cfg"],
        context_text="# AGENTS.md\n",
    )  # fmt: skip


def limits(**kw: object) -> DispatchLimits:
    base: dict[str, object] = {
        "timeout_s": 1200.0, "task_usd": 2.0, "allowed_commands": (LINT, UNIT),
    }  # fmt: skip
    base.update(kw)
    return DispatchLimits(**base)  # type: ignore[arg-type]


def prompt(tool: str, text: str = "Task T-002: do the thing.\n") -> RenderedTaskPrompt:
    return RenderedTaskPrompt(ToolName(tool), "T-002", text)


def run(stdout: str, code: int = 0, *, timed_out: bool = False) -> ProcessResult:
    return ProcessResult(("x",), code, stdout.encode(), b"", timed_out, False, 1.0)


def final_output(tool: str, text: str) -> str:
    """What the tool prints for a final message `text`, in its own format."""
    if tool == "claude":
        return json.dumps({"type": "result", "subtype": "success", "is_error": False,
                           "total_cost_usd": 0.1, "result": text}) + "\n"  # fmt: skip
    if tool == "codex":
        item = {"type": "item.completed", "item": {"type": "agent_message", "text": text}}
        return json.dumps(item) + "\n" + json.dumps({"type": "turn.completed"}) + "\n"
    if tool == "gemini":
        return json.dumps({"response": text, "stats": {}}) + "\n"
    return json.dumps({"type": "assistant.message", "data": {"content": text}}) + "\n"


# ---------------------------------------------------------------- detection


@pytest.mark.parametrize("tool", TOOLS)
def test_a_missing_tool_is_not_found(tool: str) -> None:
    cls = type(_make(tool))
    found = cls(which=lambda _name: None).detect(flags=True)
    assert (found.found, found.dispatchable) == (False, False)


@pytest.mark.parametrize("tool", ["claude", "codex", "gemini"])
def test_the_stub_offers_every_flag_dispatch_needs(tool: str) -> None:
    caps = _make(tool).detect(flags=True)
    assert (caps.flags_checked, caps.missing, caps.dispatchable) == (True, (), True)
    assert caps.version is not None


def test_copilot_is_never_dispatchable() -> None:
    """ADR-0025: every flag is there, and Copilot is still render-only."""
    caps = _make("copilot").detect(flags=True)
    assert caps.found and caps.version == "1.0.109" and caps.flags_checked
    assert caps.missing == copilot.UNVERIFIED
    assert not caps.dispatchable


@pytest.mark.parametrize(
    ("tool", "flag"), [(t, f) for t, flags in REQUIRED_FLAGS.items() for f in flags]
)
def test_a_missing_flag_fails_closed(tool: str, flag: str, tmp_path: Path) -> None:
    stub = tmp_path / "home" / ".stub-claude"
    stub.mkdir(parents=True)
    (stub / "scenario.json").write_text(json.dumps({"help_drop": [flag]}), encoding="utf-8")
    caps = _make(tool).detect(flags=True)
    assert any(flag in m for m in caps.missing), caps.missing
    assert not caps.dispatchable


def test_a_missing_choice_fails_closed(tmp_path: Path) -> None:
    stub = tmp_path / "home" / ".stub-claude"
    stub.mkdir(parents=True)
    (stub / "scenario.json").write_text(json.dumps({"help_drop": ["workspace-write"]}), "utf-8")
    caps = _make("codex").detect(flags=True)
    assert "workspace-write" in caps.missing


@pytest.mark.parametrize("tool", ["codex", "gemini", "copilot"])
def test_an_unreadable_help_fails_closed(tool: str, tmp_path: Path) -> None:
    broken = tmp_path / tool
    broken.write_text('#!/bin/sh\n[ "$1" = --version ] && echo 9.9.9 && exit 0\nexit 3\n')
    broken.chmod(0o755)
    cls = type(_make(tool))
    caps = cls(which=lambda _n: str(broken)).detect(flags=True)
    assert caps.version == "9.9.9" and not caps.dispatchable


@pytest.mark.parametrize("tool", ["codex", "gemini", "copilot"])
def test_dispatch_needs_detection_first(tool: str, tmp_path: Path) -> None:
    with pytest.raises(MissingCapability, match="checked for the flags"):
        _make(tool).build_invocation(prompt(tool), limits(), workspace(tmp_path))


# ---------------------------------------------------------------- rendering


@pytest.mark.parametrize("tool", TOOLS)
def test_every_tool_renders_the_same_checked_prompt(tool: str) -> None:
    ctx = clinic_context()
    spec = compile_task_spec(clinic_task("T-002"), ctx, approval="approved")
    rendered = _make(tool).render_prompt(spec, ctx)
    assert rendered.tool is ToolName(tool)
    assert rendered.task_id == spec.id and f"# Task {spec.id}" in rendered.text
    assert "AIPM-BLOCKED" in rendered.text


@pytest.mark.parametrize("tool", TOOLS)
def test_every_tool_lists_agents_md(tool: str) -> None:
    assert "AGENTS.md" in {f.path for f in _make(tool).context_files(clinic_context())}


# ---------------------------------------------------------------- the invocation


@pytest.mark.usefixtures("copilot_on")
@pytest.mark.parametrize("tool", TOOLS)
def test_the_invocation_is_fixed_fragments_and_an_allowlisted_env(
    tool: str, tmp_path: Path
) -> None:
    adapter = ready(tool)
    ws = workspace(tmp_path)
    inv = adapter.build_invocation(prompt(tool), limits(), ws)
    check_forbidden_flags(adapter.name, inv.argv)
    assert Path(inv.argv[0]).name in (tool, "python3", "node") or inv.argv[0].endswith(tool)
    key, value = AGENT_KEYS[tool]
    assert inv.env[key] == value
    for name, env_value in inv.env.items():
        assert "not-a-real-secret" not in env_value or name == key, name
    assert inv.env[adapter.config_home.env_var] == str(ws.config_home)
    allowed = {*BASE_ENV_ALLOWLIST, *PROXY_ENV, key, adapter.config_home.env_var, "TMPDIR"}
    extra = {"TERM", "NO_COLOR", "CI"}
    fixed = {k for k, _ in getattr(adapter, "agent_env", ())} | set(claude_code.AGENT_ENV)
    assert set(inv.env) <= allowed | extra | fixed
    assert inv.api_domains == adapter.api_domains and inv.api_domains
    for path, _text in inv.files:
        assert path.parent == ws.context_dir


@pytest.mark.usefixtures("copilot_on")
@pytest.mark.parametrize("tool", TOOLS)
def test_the_tool_key_must_be_set(tool: str, tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    adapter = ready(tool)
    monkeypatch.delenv(AGENT_KEYS[tool][0])
    with pytest.raises(MissingCapability, match=AGENT_KEYS[tool][0]):
        adapter.build_invocation(prompt(tool), limits(), workspace(tmp_path))


@pytest.mark.usefixtures("copilot_on")
@pytest.mark.parametrize("tool", TOOLS)
def test_a_pass_env_name_is_passed_and_nothing_else(
    tool: str, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("MY_TOOL_SETTING", "on")
    monkeypatch.setenv("UNLISTED_SETTING", "on")
    inv = ready(tool).build_invocation(
        prompt(tool), limits(pass_env=("MY_TOOL_SETTING",)), workspace(tmp_path)
    )
    assert inv.env.get("MY_TOOL_SETTING") == "on" and "UNLISTED_SETTING" not in inv.env


@pytest.mark.usefixtures("copilot_on")
@pytest.mark.parametrize("tool", TOOLS)
def test_an_oversize_prompt_is_refused(tool: str, tmp_path: Path) -> None:
    big = "x" * (max(MAX_PROMPT_BYTES, claude_code.MAX_PROMPT_STDIN) + 1)
    with pytest.raises(UsageError):
        ready(tool).build_invocation(prompt(tool, big), limits(), workspace(tmp_path))


@pytest.mark.usefixtures("copilot_on")
@pytest.mark.parametrize("tool", ["claude", "gemini", "copilot"])
def test_a_gate_word_a_rule_cannot_match_literally_is_refused(tool: str, tmp_path: Path) -> None:
    odd = limits(allowed_commands=(("uv", "run", "pytest", "a b'c"),))
    with pytest.raises(PolicyViolation) as info:
        ready(tool).build_invocation(prompt(tool), odd, workspace(tmp_path))
    assert info.value.exit_code is ExitCode.SECURITY_VIOLATION


@pytest.mark.parametrize("tool", ["codex", "gemini"])
def test_the_preview_matches_the_dispatch_argv_but_for_the_prompt_file(
    tool: str, tmp_path: Path
) -> None:
    adapter = ready(tool)
    ws = workspace(tmp_path)
    assert (
        adapter.preview_argv(limits(), ws)
        == adapter.build_invocation(prompt(tool), limits(), ws).argv
    )


def test_codex_argv(tmp_path: Path) -> None:
    argv = ready("codex").preview_argv(limits(), workspace(tmp_path))
    assert argv[1:] == (*codex.FIXED, "-")


def test_gemini_rules_follow_the_gates_and_the_sandbox_follows_srt(tmp_path: Path) -> None:
    adapter = ready("gemini")
    ws = workspace(tmp_path)
    argv = adapter.build_invocation(prompt("gemini"), limits(), ws).argv
    rules = [argv[i + 1] for i, a in enumerate(argv) if a == "--allowed-tools"]
    assert rules == [f"run_shell_command({' '.join(LINT)})", f"run_shell_command({' '.join(UNIT)})"]
    assert "--sandbox" not in argv
    native = adapter.build_invocation(prompt("gemini"), limits(native_sandbox=True), ws).argv
    assert "--sandbox" in native
    none = adapter.build_invocation(prompt("gemini"), limits(allowed_commands=()), ws).argv
    assert "--allowed-tools" not in none


@pytest.mark.parametrize("name", [".gemini", ".env", ".env.local", ".GEMINI", ".Env"])
def test_gemini_refuses_a_worktree_with_settings_it_would_load(name: str, tmp_path: Path) -> None:
    ws = workspace(tmp_path)
    (ws.root / name).mkdir() if name.casefold() == ".gemini" else (ws.root / name).write_text(
        "X=1\n"
    )
    with pytest.raises(PolicyViolation, match=name) as info:
        ready("gemini").build_invocation(prompt("gemini"), limits(), ws)
    assert info.value.exit_code is ExitCode.SECURITY_VIOLATION


def test_gemini_seeds_only_documented_settings() -> None:
    ((rel, text),) = gemini.CONFIG_HOME.seed
    assert rel in gemini.CONFIG_HOME.protected
    assert json.loads(text) == {
        "context": {"fileName": ["AGENTS.md", "GEMINI.md"]},
        "general": {"enableAutoUpdate": False},
        "privacy": {"usageStatisticsEnabled": False},
    }


@pytest.mark.usefixtures("copilot_on")
def test_copilot_reads_its_prompt_from_a_file_it_cannot_write(tmp_path: Path) -> None:
    ws = workspace(tmp_path)
    inv = ready("copilot").build_invocation(prompt("copilot"), limits(), ws)
    ((path, text),) = inv.files
    assert inv.stdin == b"" and text == prompt("copilot").text
    assert str(path) in inv.argv[inv.argv.index("-p") + 1]
    assert inv.argv[inv.argv.index("--add-dir") + 1] == str(ws.context_dir)
    tools = [inv.argv[i + 1] for i, a in enumerate(inv.argv) if a == "--allow-tool"]
    assert tools == ["write", f"shell({' '.join(LINT)})", f"shell({' '.join(UNIT)})"]


# ---------------------------------------------------------------- output


@pytest.mark.parametrize("tool", ["claude", "codex", "gemini"])
def test_aipm_done_and_claims_carry_no_authority(tool: str) -> None:
    out = final_output(tool, "All tests pass.\nAIPM-DONE\n")
    parsed = _make(tool).parse_result(run(out))
    assert parsed.saw_result and parsed.blocked_question is None


@pytest.mark.parametrize("tool", ["claude", "codex", "gemini"])
def test_the_blocked_question_is_cleaned_and_capped(tool: str) -> None:
    question = "Which \x1b[31mdatabase\u2028should I use?\U000e0041 " + "x" * 500
    parsed = _make(tool).parse_result(run(final_output(tool, f"Hmm.\nAIPM-BLOCKED: {question}")))
    got = parsed.blocked_question or ""
    assert got.startswith("Which") and "\x1b" not in got and "\u2028" not in got
    assert "\n" not in got and len(got) <= MAX_QUESTION


def test_copilot_reads_no_question_from_an_undocumented_schema() -> None:
    parsed = _make("copilot").parse_result(run(final_output("copilot", "AIPM-BLOCKED: why?")))
    assert parsed.blocked_question is None and not parsed.saw_result


@pytest.mark.parametrize("tool", TOOLS)
def test_garbage_output_is_no_result(tool: str) -> None:
    parsed = _make(tool).parse_result(run("not json\n{broken\n[1, 2]\n", 1, timed_out=True))
    assert (parsed.saw_result, parsed.exit_code, parsed.timed_out) == (False, 1, True)
    assert parsed.cost_usd is None and parsed.blocked_question is None


@pytest.mark.parametrize("tool", ["codex", "gemini"])
def test_an_error_is_reported_and_no_cost_is_claimed(tool: str) -> None:
    out = (
        json.dumps({"type": "turn.failed", "error": {"message": "x"}}) + "\n"
        if tool == "codex"
        else json.dumps({"response": "", "error": {"message": "x"}}) + "\n"
    )
    parsed = _make(tool).parse_result(run(out, 1))
    assert (parsed.saw_result, parsed.is_error, parsed.subtype) == (True, True, "error")
    assert parsed.cost_usd is None and parsed.session_id is None


def test_gemini_reads_a_result_after_other_lines() -> None:
    out = "Loaded cached credentials.\n" + json.dumps({"response": "AIPM-BLOCKED: q?"}) + "\n"
    assert _make("gemini").parse_result(run(out)).blocked_question == "q?"


def test_gemini_stops_its_dotenv_search_at_the_worktree_parent(tmp_path: Path) -> None:
    """Gemini walks up from its working directory for `.env`: an empty guard in the worktree's
    parent ends the walk before the user's home (step 08 security review)."""
    ws = workspace(tmp_path)
    inv = ready("gemini").build_invocation(prompt("gemini"), limits(), ws)
    guard = ws.root.parent / ".env"
    assert guard.is_file() and guard.stat().st_size == 0
    assert inv.env["GEMINI_SANDBOX"] == "false"
    ready("gemini").build_invocation(prompt("gemini"), limits(), ws)  # an empty guard is reused


def test_gemini_refuses_a_guard_that_is_not_empty(tmp_path: Path) -> None:
    ws = workspace(tmp_path)
    (ws.root.parent / ".env").write_text("GEMINI_SANDBOX=false\n")
    with pytest.raises(PolicyViolation, match="empty file"):
        ready("gemini").build_invocation(prompt("gemini"), limits(), ws)
