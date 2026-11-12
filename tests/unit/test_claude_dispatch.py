"""Claude Code dispatch (ARCHITECTURE §11, ADR-0023): the flag check, the invocation built from
fixed fragments, and the parsing of its stream-json output."""

import json
from pathlib import Path

import pytest

from aipm.adapters import claude_code
from aipm.adapters.base import DispatchLimits, RenderedTaskPrompt
from aipm.adapters.claude_code import ClaudeCodeAdapter, allowed_tools, blocked_question, help_flags
from aipm.domain.errors import MissingCapability, PolicyViolation, UsageError
from aipm.domain.models import ToolName, Workspace
from aipm.execution.process import ProcessResult
from tests.conftest import REPO_ROOT, FakeSecrets

STUB_BIN = REPO_ROOT / "tests" / "fakes" / "bin"
SESSION = "0f8fad5b-d9cb-469f-a165-70867728950e"
UNIT = ("uv", "run", "--frozen", "--offline", "pytest")
LINT = ("uv", "run", "--frozen", "--offline", "ruff", "check")


@pytest.fixture(autouse=True)
def fresh_cache(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    claude_code._detected.clear()  # pyright: ignore[reportPrivateUsage]
    monkeypatch.setenv("HOME", str(tmp_path / "home"))
    monkeypatch.setenv("ANTHROPIC_API_KEY", "aipm-fake-anthropic-key-not-a-real-secret-0001")


def stub_which(name: str) -> str | None:
    path = STUB_BIN / name
    return str(path) if path.is_file() else None


def ready_adapter() -> ClaudeCodeAdapter:
    adapter = ClaudeCodeAdapter(which=stub_which)
    caps = adapter.detect(flags=True)
    assert caps.dispatchable, caps.missing
    return adapter


def workspace(tmp_path: Path, resume: str | None = None) -> Workspace:
    dirs = {name: tmp_path / name for name in ("wt", "tmp", "ctx", "cfg")}
    for path in dirs.values():
        path.mkdir(exist_ok=True)
    return Workspace(
        root=dirs["wt"], temp_dir=dirs["tmp"], context_dir=dirs["ctx"], config_home=dirs["cfg"],
        context_text="# AGENTS.md\n", resume_session=resume,
    )  # fmt: skip


def limits(**kw: object) -> DispatchLimits:
    base: dict[str, object] = {
        "timeout_s": 1200.0, "task_usd": 2.0, "allowed_commands": (LINT, UNIT),
    }  # fmt: skip
    base.update(kw)
    return DispatchLimits(**base)  # type: ignore[arg-type]


PROMPT = RenderedTaskPrompt(ToolName.CLAUDE, "T-002", "Task T-002: do the thing.\n")


# ---------------------------------------------------------------- detection


def test_help_flags_reads_options_and_the_file_form() -> None:
    text = "  -p, --print  x\n  --bare  context via --append-system-prompt[-file], --add-dir\n"
    assert help_flags(text) == frozenset(
        {"--print", "--bare", "--append-system-prompt", "--append-system-prompt-file", "--add-dir"}
    )


def test_the_stub_offers_every_flag_dispatch_needs() -> None:
    caps = ClaudeCodeAdapter(which=stub_which).detect(flags=True)
    assert (caps.flags_checked, caps.missing, caps.dispatchable) == (True, (), True)


def test_the_flag_check_runs_once_per_executable(monkeypatch: pytest.MonkeyPatch) -> None:
    calls: list[list[str]] = []
    real = claude_code.run_safe

    def counting(argv: list[str], **kwargs: object) -> ProcessResult:
        calls.append(list(argv[1:]))
        return real(argv, **kwargs)  # type: ignore[arg-type]

    monkeypatch.setattr(claude_code, "run_safe", counting)
    ClaudeCodeAdapter(which=stub_which).detect(flags=True)
    ClaudeCodeAdapter(which=stub_which).detect(flags=True)
    ClaudeCodeAdapter(which=stub_which).detect()
    assert calls == [["--version"], ["--help"]]


@pytest.mark.parametrize(
    ("drop", "missing"),
    [
        ("--strict-mcp-config", "--strict-mcp-config"),
        ("--setting-sources", "--setting-sources"),
        ("dontAsk", "--permission-mode dontAsk"),
        ("--permission-prompts", "--permission-prompts"),
        ("stream-json", "--output-format stream-json"),
        ("[-file]", "--append-system-prompt-file"),
    ],
)
def test_a_missing_flag_fails_closed(drop: str, missing: str, tmp_path: Path) -> None:
    stub = tmp_path / "home" / ".stub-claude"
    stub.mkdir(parents=True)
    (stub / "scenario.json").write_text(json.dumps({"help_drop": [drop]}), encoding="utf-8")
    caps = ClaudeCodeAdapter(which=stub_which).detect(flags=True)
    assert missing in caps.missing
    assert not caps.dispatchable


def test_help_that_cannot_be_read_is_a_missing_capability(tmp_path: Path) -> None:
    odd = tmp_path / "claude"
    odd.write_text('#!/bin/sh\n[ "$1" = --version ] && echo 2.1.300 && exit 0\nexit 3\n')
    odd.chmod(0o755)
    caps = ClaudeCodeAdapter(which=lambda _n: str(odd)).detect(flags=True)
    assert caps.missing == ("--help",)
    assert not caps.dispatchable


def test_help_is_not_read_without_a_version(tmp_path: Path) -> None:
    odd = tmp_path / "claude"
    odd.write_text("#!/bin/sh\necho no version\n")
    odd.chmod(0o755)
    caps = ClaudeCodeAdapter(which=lambda _n: str(odd)).detect(flags=True)
    assert (caps.version, caps.flags_checked) == (None, False)


def test_a_claude_inside_the_repository_is_never_used(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    planted = repo / ".venv" / "bin" / "claude"
    planted.parent.mkdir(parents=True)
    planted.write_text("#!/bin/sh\necho 2.1.300\n")
    planted.chmod(0o755)
    caps = ClaudeCodeAdapter(which=lambda _n: str(planted)).detect(flags=True, repo=repo)
    assert not caps.found
    outside = ClaudeCodeAdapter(which=stub_which).detect(flags=True, repo=repo)
    assert outside.dispatchable


def test_the_default_lookup_skips_repository_path_entries(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    repo = tmp_path / "repo"
    (repo / "bin").mkdir(parents=True)
    planted = repo / "bin" / "claude"
    planted.write_text("#!/bin/sh\necho 2.1.300\n")
    planted.chmod(0o755)
    monkeypatch.setenv("PATH", f"{repo / 'bin'}:{STUB_BIN}:/usr/bin:/bin")
    caps = ClaudeCodeAdapter().detect(flags=True, repo=repo)
    assert caps.path == str((STUB_BIN / "claude").resolve())


# ---------------------------------------------------------------- invocation


def test_the_invocation_is_built_from_fixed_fragments(tmp_path: Path) -> None:
    ws = workspace(tmp_path)
    inv = ready_adapter().build_invocation(PROMPT, limits(), ws)
    ((context_file, context_text),) = inv.files
    assert context_file.parent == ws.context_dir
    assert context_file.name.startswith("agents-")
    assert context_text == "# AGENTS.md\n"
    assert list(inv.argv) == [
        str((STUB_BIN / "claude").resolve()),
        "--bare", "-p", "--output-format", "stream-json", "--verbose",
        "--permission-mode", "dontAsk", "--permission-prompts", "none",
        "--setting-sources", "user", "--strict-mcp-config",
        "--allowedTools",
        "Read,Edit,Write,Glob,Grep,"
        "Bash(uv run --frozen --offline ruff check),Bash(uv run --frozen --offline ruff check *),"
        "Bash(uv run --frozen --offline pytest),Bash(uv run --frozen --offline pytest *)",
        "--max-budget-usd", "2.00",
        "--append-system-prompt-file", str(context_file),
    ]  # fmt: skip
    assert inv.stdin == PROMPT.text.encode()
    assert inv.api_domains == ("api.anthropic.com",)


def test_each_dispatch_gets_a_new_context_file_name(tmp_path: Path) -> None:
    adapter = ready_adapter()
    ws = workspace(tmp_path)
    first = adapter.build_invocation(PROMPT, limits(), ws).files[0][0]
    second = adapter.build_invocation(PROMPT, limits(), ws).files[0][0]
    assert first != second


def test_the_environment_is_built_not_copied(
    tmp_path: Path, fake_secrets: FakeSecrets, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("HTTPS_PROXY", "http://proxy.example.invalid:3128")
    monkeypatch.setenv("PROJECT_VAR", "passed")
    ws = workspace(tmp_path)
    env = ready_adapter().build_invocation(PROMPT, limits(pass_env=("PROJECT_VAR",)), ws).env
    assert env["CLAUDE_CONFIG_DIR"] == str(ws.config_home)
    assert env["TMPDIR"] == str(ws.temp_dir)
    assert env["DISABLE_AUTOUPDATER"] == "1"
    assert env["CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC"] == "1"
    assert env["HTTPS_PROXY"] == "http://proxy.example.invalid:3128"
    assert env["PROJECT_VAR"] == "passed"
    assert env["ANTHROPIC_API_KEY"]
    others = {k: v for k, v in env.items() if k != "ANTHROPIC_API_KEY"}
    fake_secrets.assert_absent(json.dumps(others))
    assert "GITHUB_TOKEN" not in env
    assert "OPENAI_API_KEY" not in env


def test_bare_mode_needs_the_api_key(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    adapter = ready_adapter()
    monkeypatch.delenv("ANTHROPIC_API_KEY")
    with pytest.raises(MissingCapability, match="ANTHROPIC_API_KEY"):
        adapter.build_invocation(PROMPT, limits(), workspace(tmp_path))
    inv = adapter.build_invocation(PROMPT, limits(bare=False), workspace(tmp_path))
    assert "--bare" not in inv.argv
    assert "ANTHROPIC_API_KEY" not in inv.env
    # Without --bare, repository and local settings and MCP servers stay out (ADR-0023).
    assert {"--setting-sources", "user", "--strict-mcp-config"} <= set(inv.argv)


def test_a_fix_attempt_resumes_a_validated_session(tmp_path: Path) -> None:
    adapter = ready_adapter()
    inv = adapter.build_invocation(PROMPT, limits(), workspace(tmp_path, resume=SESSION))
    assert inv.argv[-2:] == ("--resume", SESSION)
    for bad in ("--dangerously-skip-permissions", "latest", SESSION.upper(), f"{SESSION} x"):
        with pytest.raises(PolicyViolation, match="session"):
            adapter.build_invocation(PROMPT, limits(), workspace(tmp_path, resume=bad))


def test_forbidden_flags_are_checked_on_the_final_argv(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    seen: list[tuple[str, ...]] = []
    real = claude_code.check_forbidden_flags

    def recording(tool: ToolName, argv: tuple[str, ...], *, allow_auto_mode: bool = False) -> None:
        seen.append(argv)
        real(tool, argv, allow_auto_mode=allow_auto_mode)

    monkeypatch.setattr(claude_code, "check_forbidden_flags", recording)
    inv = ready_adapter().build_invocation(PROMPT, limits(), workspace(tmp_path, resume=SESSION))
    assert seen == [inv.argv]


@pytest.mark.parametrize(
    "word", ["pytest -k", "a,b", "x)", "(x", "*", "$HOME", "a'b", 'a"b', "a;b", "a|b", "é", ""]
)
def test_a_gate_word_a_rule_cannot_match_literally_is_refused(word: str) -> None:
    with pytest.raises(PolicyViolation, match="cannot be allowed"):
        allowed_tools([("uv", "run", word)])


def test_allowed_tools_without_gates_and_with_duplicates() -> None:
    assert allowed_tools([]) == "Read,Edit,Write,Glob,Grep"
    assert allowed_tools([(), UNIT, UNIT]).count("Bash(") == 2


@pytest.mark.parametrize(("usd", "shown"), [(2.0, "2.00"), (0.001, "0.01"), (10.555, "10.55")])
def test_the_task_budget_is_passed_in_dollars(tmp_path: Path, usd: float, shown: str) -> None:
    inv = ready_adapter().build_invocation(PROMPT, limits(task_usd=usd), workspace(tmp_path))
    assert inv.argv[inv.argv.index("--max-budget-usd") + 1] == shown


@pytest.mark.parametrize("usd", [0.0, -1.0, float("nan"), float("inf")])
def test_a_task_budget_that_is_not_an_amount_is_refused(tmp_path: Path, usd: float) -> None:
    with pytest.raises(UsageError, match="positive amount"):
        ready_adapter().build_invocation(PROMPT, limits(task_usd=usd), workspace(tmp_path))


def test_a_prompt_larger_than_claude_reads_is_refused(tmp_path: Path) -> None:
    huge = RenderedTaskPrompt(ToolName.CLAUDE, "T-002", "x" * (10 * 1_048_576 + 1))
    with pytest.raises(UsageError, match="larger than Claude Code reads"):
        ready_adapter().build_invocation(huge, limits(), workspace(tmp_path))


# ---------------------------------------------------------------- output


def run(stdout: str, returncode: int | None = 0, timed_out: bool = False) -> ProcessResult:
    return ProcessResult(("claude",), returncode, stdout.encode(), b"", timed_out, False, 1.0)


def result_line(**fields: object) -> str:
    event: dict[str, object] = {
        "type": "result", "subtype": "success", "is_error": False, "total_cost_usd": 0.42,
        "session_id": SESSION, "result": "Done.", "num_turns": 3, "usage": {"input_tokens": 9},
    }  # fmt: skip
    event.update(fields)
    return json.dumps(event)


def test_the_final_result_event_is_read() -> None:
    out = "\n".join(['{"type":"system","subtype":"init"}', "not json", result_line(), ""])
    parsed = claude_code.create().parse_result(run(out))
    assert parsed.saw_result
    assert (parsed.cost_usd, parsed.session_id, parsed.is_error, parsed.subtype) == (
        0.42, SESSION, False, "success",
    )  # fmt: skip
    assert parsed.blocked_question is None


def test_the_last_result_wins_and_a_bad_one_counts_as_none() -> None:
    adapter = claude_code.create()
    out = "\n".join([result_line(total_cost_usd=0.1), result_line(total_cost_usd=0.9)])
    assert adapter.parse_result(run(out)).cost_usd == 0.9
    for bad in (
        result_line(session_id="../../etc"),
        result_line(total_cost_usd=-1),
        result_line(total_cost_usd="NaN"),
        result_line(subtype="Error Max Budget"),
        result_line(is_error="yes"),
        '["result"]',
        '{"type": "assistant", "result": "x"}',
    ):
        parsed = adapter.parse_result(run(bad, returncode=1))
        assert not parsed.saw_result
        assert parsed.exit_code == 1


def test_a_killed_agent_has_no_result() -> None:
    parsed = claude_code.create().parse_result(run('{"type":"system"}\n', 143, timed_out=True))
    assert (parsed.saw_result, parsed.exit_code, parsed.timed_out, parsed.cost_usd) == (
        False, 143, True, None,
    )  # fmt: skip


def test_aipm_done_and_claims_carry_no_authority() -> None:
    text = "All tests pass.\nAIPM-DONE"
    parsed = claude_code.create().parse_result(run(result_line(result=text)))
    assert parsed.blocked_question is None


def test_the_last_blocked_line_is_sanitized_and_capped() -> None:
    text = (
        "AIPM-BLOCKED: first\nwork\n"
        "  AIPM-BLOCKED: Which \x1b[31mdatabase\x1b[0m\u200b should   I use? " + "x" * 400
    )
    parsed = claude_code.create().parse_result(run(result_line(result=text)))
    question = parsed.blocked_question
    assert question is not None
    assert question.startswith("Which database should I use? x")
    assert "\x1b" not in question
    assert "\u200b" not in question
    assert len(question) == 300


def test_an_empty_blocked_line_is_ignored() -> None:
    assert blocked_question("AIPM-BLOCKED:   \n") is None
    assert blocked_question("nothing here") is None


def test_a_huge_result_keeps_its_end(tmp_path: Path) -> None:
    text = "x" * 200_000 + "\nAIPM-BLOCKED: need a key"
    parsed = claude_code.create().parse_result(run(result_line(result=text)))
    assert parsed.blocked_question == "need a key"
