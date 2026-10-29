"""The Claude Code adapter (ARCHITECTURE §11), the registry and the clipboard helper.

`detect` runs the stub `tests/fakes/bin/claude` through `run_safe`, once per executable.
"""

import os
from pathlib import Path

import pytest

from aipm.adapters import claude_code, registry
from aipm.adapters.base import DispatchLimits, RenderedTaskPrompt
from aipm.domain.errors import ExitCode, NotAvailable, UsageError
from aipm.domain.models import ToolName, Workspace
from aipm.execution import clipboard
from aipm.execution.process import ProcessResult
from tests.conftest import REPO_ROOT
from tests.fakes.project import clinic_context

STUB_BIN = REPO_ROOT / "tests" / "fakes" / "bin"


@pytest.fixture(autouse=True)
def fresh_cache() -> None:
    claude_code._detected.clear()  # pyright: ignore[reportPrivateUsage]


def stub_which(name: str) -> str | None:
    path = STUB_BIN / name
    return str(path) if path.is_file() else None


def test_detect_reads_the_version_of_the_stub() -> None:
    caps = claude_code.ClaudeCodeAdapter(which=stub_which).detect()
    assert caps.tool is ToolName.CLAUDE
    assert caps.found
    assert caps.version == "2.1.300"
    assert caps.path == os.path.realpath(STUB_BIN / "claude")


def test_detect_runs_the_tool_once_per_executable(monkeypatch: pytest.MonkeyPatch) -> None:
    calls: list[list[str]] = []
    real = claude_code.run_safe

    def counting(argv: list[str], **kwargs: object) -> ProcessResult:
        calls.append(list(argv))
        return real(argv, **kwargs)  # type: ignore[arg-type]

    monkeypatch.setattr(claude_code, "run_safe", counting)
    first = claude_code.ClaudeCodeAdapter(which=stub_which).detect()
    again = claude_code.ClaudeCodeAdapter(which=stub_which).detect()
    assert first == again
    assert len(calls) == 1
    assert calls[0][1:] == ["--version"]


def test_detect_without_claude() -> None:
    caps = claude_code.ClaudeCodeAdapter(which=lambda _n: None).detect()
    assert not caps.found
    assert caps.version is None


def test_detect_with_an_unreadable_version(tmp_path: Path) -> None:
    odd = tmp_path / "claude"
    odd.write_text("#!/bin/sh\necho 'no version here'\n", encoding="utf-8")
    odd.chmod(0o755)
    caps = claude_code.ClaudeCodeAdapter(which=lambda _n: str(odd)).detect()
    assert caps.found
    assert caps.version is None


def test_detect_when_the_tool_cannot_run(tmp_path: Path) -> None:
    broken = tmp_path / "claude"
    broken.write_text("not a program\n", encoding="utf-8")
    broken.chmod(0o644)
    caps = claude_code.ClaudeCodeAdapter(which=lambda _n: str(broken)).detect()
    assert caps.found
    assert caps.version is None


def test_dispatch_arrives_in_v03() -> None:
    adapter = claude_code.create()
    prompt = RenderedTaskPrompt(ToolName.CLAUDE, "T-001", "x")
    with pytest.raises(NotImplementedError, match=r"v0\.3"):
        adapter.build_invocation(prompt, DispatchLimits(), Workspace())
    with pytest.raises(NotImplementedError, match=r"v0\.3"):
        adapter.parse_result(ProcessResult(("x",), 0, b"", b"", False, False, 0.0))


def test_context_files_are_agents_md_and_claude_md() -> None:
    files = claude_code.create().context_files(clinic_context())
    assert [f.path for f in files] == ["AGENTS.md", "CLAUDE.md"]
    assert files[1].block.startswith("@AGENTS.md\n")


def test_rendered_prompt_size_is_in_bytes() -> None:
    assert RenderedTaskPrompt(ToolName.CLAUDE, "T-001", "é").size == 2


# ---------------------------------------------------------------- registry


def test_parse_tool() -> None:
    assert registry.parse_tool(None, ToolName.CLAUDE) is ToolName.CLAUDE
    assert registry.parse_tool(" Codex ", ToolName.CLAUDE) is ToolName.CODEX
    with pytest.raises(UsageError, match="unknown tool"):
        registry.parse_tool("cursor", ToolName.CLAUDE)


def test_only_claude_has_an_adapter_in_v01() -> None:
    assert isinstance(registry.get_adapter(ToolName.CLAUDE), claude_code.ClaudeCodeAdapter)
    for tool in (ToolName.CODEX, ToolName.COPILOT, ToolName.GEMINI):
        with pytest.raises(NotAvailable) as info:
            registry.get_adapter(tool)
        assert info.value.exit_code is ExitCode.USAGE
        assert "v0.4" in info.value.message


# ---------------------------------------------------------------- clipboard


def fake_tool(directory: Path, name: str) -> Path:
    """A clipboard stub that saves stdin (and its arguments) under $HOME."""
    path = directory / name
    path.write_text('#!/bin/sh\necho "$@" > "$HOME/args"\ncat > "$HOME/clip"\n', encoding="utf-8")
    path.chmod(0o755)
    return path


@pytest.mark.parametrize(
    ("platform", "display", "tool", "args"),
    [
        ("darwin", {}, "pbcopy", ""),
        ("linux", {"WAYLAND_DISPLAY": "wayland-0"}, "wl-copy", ""),
        ("linux", {"DISPLAY": ":0"}, "xclip", "-selection clipboard"),
    ],
)
def test_copy_text_uses_the_platform_tool(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, platform: str,
    display: dict[str, str], tool: str, args: str,
) -> None:  # fmt: skip
    fake_tool(tmp_path, tool)

    def which(name: str) -> str | None:
        return str(tmp_path / name) if (tmp_path / name).exists() else None

    monkeypatch.setattr(clipboard.shutil, "which", which)
    environ = {"HOME": str(tmp_path), "PATH": "/usr/bin:/bin", "SECRET_TOKEN": "nope", **display}
    used = clipboard.copy_text("prompt text\n", cwd=tmp_path, environ=environ, platform=platform)
    assert used == tool
    assert (tmp_path / "clip").read_text(encoding="utf-8") == "prompt text\n"
    assert (tmp_path / "args").read_text(encoding="utf-8").strip() == args


def test_copy_text_without_a_tool_returns_none(tmp_path: Path) -> None:
    assert clipboard.copy_text("x", cwd=tmp_path, environ={}, platform="linux") is None


def test_copy_text_with_a_failing_tool_returns_none(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    failing = tmp_path / "pbcopy"
    failing.write_text("#!/bin/sh\nexit 1\n", encoding="utf-8")
    failing.chmod(0o755)
    monkeypatch.setattr(clipboard.shutil, "which", lambda _n: str(failing))
    assert clipboard.copy_text("x", cwd=tmp_path, environ={}, platform="darwin") is None
