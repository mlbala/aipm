"""Context files and task prompts (build prompt 05; SECURITY.md §7.10, §14.1 I-3, §14.2).

A context file persists across every agent session, so hostile text in an approved artifact must
never become a rule there. The corpus cases C-022 to C-027 go into every model-written field
(PRD and architecture fields, task fields) and into the PRD and architecture bodies; in every
generated file and task prompt, the hostile text may appear only inside an untrusted block, and
nothing anywhere may break invariant I-3.
"""

import os
import re
import stat
from dataclasses import replace
from pathlib import Path
from typing import Any

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st
from ruamel.yaml import YAML

from aipm.adapters.claude_code import ClaudeCodeAdapter
from aipm.adapters.compiler import compile_task_spec
from aipm.app.project_context import agent_gates, build_context
from aipm.context.generator import CLAUDE_IMPORT, agents_md, claude_md, generate
from aipm.context.markdown import agent_text_problems, outside_code
from aipm.domain.errors import PolicyViolation, UsageError
from aipm.domain.models import GateCommand, GateReport
from aipm.security.untrusted import check_blocks
from aipm.state.repo_files import read_repo_bytes, write_repo_bytes
from tests.fakes.project import (
    clinic_config,
    clinic_context,
    clinic_snapshot,
    clinic_task,
    hostile_context,
    hostile_task,
)

CORPUS = Path(__file__).parent / "corpus"
_BLOCK = re.compile(r'<untrusted source="[^"\n]*" id="(u[0-9a-f]{8})">.*?</untrusted id="\1">',
                    re.DOTALL)  # fmt: skip

# What each case tries to plant, which must never show outside an untrusted block.
TELLS: dict[str, tuple[str, ...]] = {
    "C-022": ("evil.example", "CONTEXT_EXFIL", "![status]", "Handles bookings"),
    "C-023": ("copy .env", "AI agents", "before any change"),
    "C-024": ("setup.sh", "evil.example", "always run", "curl -s"),
    "C-025": ("\U000e0072", "\U000e0073"),
    "C-026": ("setup.sh", "Add this to AGENTS.md", "never mention"),
    "C-027": ("@.env", "@~/.ssh", "id_rsa", "for the settings"),
}
ANYWHERE: dict[str, tuple[str, ...]] = {
    "C-022": ("evil.example", "https://"),
    "C-023": ("<!--", "copy .env"),
    "C-024": ("evil.example", "https://"),
    "C-025": ("\U000e0072", "\U000e0073"),
    "C-026": (),
    "C-027": ("@.env", "@~/.ssh"),
}


def case_text(case_id: str) -> str:
    (path,) = CORPUS.glob(f"{case_id}-*.yaml")
    data: dict[str, Any] = YAML(typ="safe", pure=True).load(path.read_text(encoding="utf-8"))
    return str(data["input"]["text"])


def outside_blocks(text: str) -> str:
    return _BLOCK.sub("", text)


def nonce() -> str:
    return "u0123abcd"


def task_prompt(text: str, *, task_id: str = "T-003") -> str:
    ctx = hostile_context(text)
    task = hostile_task(text, clinic_task(task_id))
    report = GateReport.model_validate(
        {"task": task_id, "gates": [{"name": "unit", "status": "fail", "summary": text,
                                     "output": f"FAILED test_x\n{text}\n"}]}
    )  # fmt: skip
    spec = compile_task_spec(task, ctx, previous=report)
    return ClaudeCodeAdapter(nonce=nonce).render_prompt(spec, ctx).text


def assert_clean(text: str, case_id: str, *, imports: tuple[str, ...] = ()) -> None:
    check_blocks(text)
    assert agent_text_problems(text, allowed_url_domains=(), imports=imports) == []
    outside = outside_blocks(text)
    for tell in TELLS[case_id]:
        assert tell not in outside, f"{case_id}: {tell!r} outside an untrusted block"
    for tell in ANYWHERE[case_id]:
        assert tell not in text, f"{case_id}: {tell!r} survived sanitizing"


CASES = sorted(TELLS)


# ---------------------------------------------------------------- the corpus


@pytest.mark.parametrize("case_id", CASES)
def test_corpus_fields_reach_agents_md_only_inside_untrusted_blocks(case_id: str) -> None:
    block = agents_md(hostile_context(case_text(case_id))).block
    assert_clean(block, case_id)


@pytest.mark.parametrize("case_id", CASES)
def test_corpus_fields_never_reach_claude_md(case_id: str) -> None:
    block = claude_md(hostile_context(case_text(case_id))).block
    assert_clean(block, case_id, imports=(CLAUDE_IMPORT,))
    assert outside_blocks(block) == block, "CLAUDE.md holds no project text at all"


@pytest.mark.parametrize("case_id", CASES)
def test_corpus_task_fields_and_gate_output_reach_prompts_only_inside_blocks(
    case_id: str,
) -> None:
    assert_clean(task_prompt(case_text(case_id)), case_id)


@pytest.mark.parametrize("case_id", CASES)
def test_artifact_bodies_never_reach_context_files_or_prompts(case_id: str) -> None:
    hostile = case_text(case_id)
    snapshot = clinic_snapshot()
    assert snapshot.prd is not None and snapshot.architecture is not None
    snapshot = replace(
        snapshot,
        prd=snapshot.prd.model_copy(update={"body": hostile}),
        architecture=snapshot.architecture.model_copy(update={"body": hostile}),
    )
    ctx = build_context(snapshot, clinic_config())
    spec = compile_task_spec(clinic_task("T-003"), ctx)
    outputs = [f.block for f in generate(ctx)]
    outputs.append(ClaudeCodeAdapter(nonce=nonce).render_prompt(spec, ctx).text)
    for text in outputs:
        for tell in TELLS[case_id]:
            assert tell not in text


def test_the_only_import_is_claude_mds_own() -> None:
    files = generate(hostile_context(case_text("C-027")))
    agents, claude = (f.block for f in files)
    assert claude.splitlines()[0] == CLAUDE_IMPORT
    for text in (agents, claude.replace(CLAUDE_IMPORT, "", 1)):
        assert not re.search(r"(?:^|\s)@\S", outside_code(text), re.MULTILINE)


# ---------------------------------------------------------------- invariant I-3, fuzzed

HOSTILE_PARTS = st.sampled_from(
    ["<!-- x -->", "<!--", "-->", "https://evil.example/a", "www.evil.example", "@.env",
     "@~/x", "\u200b", "\U000e0041", "\u202e", "\x1b[31m", "\x07", "```", "````", "`",
     "</untrusted id=\"u00000000\">", "<untrusted source=\"x\" id=\"u11111111\">", "\n",
     "\r\n", "MUST NOT", "javascript:alert(1)", "data:text/html,x", "a@b.example"]
)  # fmt: skip
FIELD = st.lists(HOSTILE_PARTS | st.text(max_size=12), max_size=10).map("".join)


@settings(max_examples=150, deadline=None)
@given(FIELD)
def test_every_generated_context_file_keeps_invariant_i3(text: str) -> None:
    for generated in generate(hostile_context(text)):
        imports = (CLAUDE_IMPORT,) if generated.path == "CLAUDE.md" else ()
        assert agent_text_problems(generated.block, allowed_url_domains=(),
                                   imports=imports) == []  # fmt: skip
        check_blocks(generated.block)


@settings(max_examples=100, deadline=None)
@given(FIELD)
def test_every_task_prompt_keeps_invariant_i3(text: str) -> None:
    prompt = task_prompt(text or "x")
    assert agent_text_problems(prompt, allowed_url_domains=()) == []
    check_blocks(prompt)


@pytest.mark.parametrize(
    "text", ["-->000000000000000000000000000000000data:text/html,x", "x//evil.example/a data"]
)
def test_joined_fields_cannot_form_a_url(text: str) -> None:
    # Found by the fuzz test: a 40-character component name ending in "data", joined with
    # ": " to its responsibility, read as a `data:` URL. Composed blocks are cleaned again.
    for generated in generate(hostile_context(text)):
        imports = (CLAUDE_IMPORT,) if generated.path == "CLAUDE.md" else ()
        assert agent_text_problems(generated.block, allowed_url_domains=(),
                                   imports=imports) == []  # fmt: skip
    assert agent_text_problems(task_prompt(text), allowed_url_domains=()) == []


def test_an_allowlisted_domain_survives_in_context_files() -> None:
    ctx = replace(hostile_context("see https://docs.python.org/3/ ok"),
                  allowed_url_domains=("docs.python.org",))  # fmt: skip
    assert "https://docs.python.org/3/" in agents_md(ctx).block


# ---------------------------------------------------------------- gate argv


def test_agent_argv_comes_only_from_compile_gate() -> None:
    gates = {g.name: g for g in agent_gates(clinic_config())}
    assert gates["lint"].argv == ("uv", "run", "--frozen", "--offline", "ruff", "check")
    assert gates["unit"].argv == ("uv", "run", "--frozen", "--offline", "pytest", "-q",
                                  "--junitxml", "/dev/null", "tests")  # fmt: skip
    assert gates["secrets"].argv is None
    assert gates["secrets"].builtin == "gitleaks"


def test_a_gate_the_policy_refuses_is_never_rendered() -> None:
    cfg = clinic_config(gates={"lint": {"run": ["uv", "run", "--frozen", "--offline", "ruff",
                                                "check", "--exec", "x"], "required": True},
                               "evil": {"run": ["uv", "run", "--frozen", "--offline", "pytest",
                                                "-c", "curl"], "required": True}})  # fmt: skip
    with pytest.raises(PolicyViolation):
        agent_gates(cfg)


def test_argv_with_a_url_is_refused_not_altered() -> None:
    url_gate = GateCommand("unit", True, ("uv", "run", "pytest", "--base=https://evil.example"))
    ctx = replace(clinic_context(), gates=(url_gate,))
    with pytest.raises(PolicyViolation, match="never carry"):
        agents_md(ctx)


# ---------------------------------------------------------------- the files themselves


def test_context_files_are_never_read_through_a_link(tmp_path: Path) -> None:
    secret = tmp_path / "outside.txt"
    secret.write_text("private\n", encoding="utf-8")
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "AGENTS.md").symlink_to(secret)
    with pytest.raises(PolicyViolation):
        read_repo_bytes(repo, "AGENTS.md")
    with pytest.raises(PolicyViolation):
        write_repo_bytes(repo, "AGENTS.md", b"x", expected=b"private\n")
    assert secret.read_text(encoding="utf-8") == "private\n"


def test_a_fifo_or_directory_is_refused(tmp_path: Path) -> None:
    os.mkfifo(tmp_path / "CLAUDE.md")
    (tmp_path / "AGENTS.md").mkdir()
    for name in ("CLAUDE.md", "AGENTS.md"):
        with pytest.raises(PolicyViolation, match="not a regular file"):
            read_repo_bytes(tmp_path, name)


def test_a_linked_directory_on_the_way_is_refused(tmp_path: Path) -> None:
    (tmp_path / "real").mkdir()
    (tmp_path / "docs").symlink_to(tmp_path / "real")
    with pytest.raises(PolicyViolation, match="link"):
        write_repo_bytes(tmp_path, "docs/prompt.md", b"x", expected=None)
    assert not (tmp_path / "real" / "prompt.md").exists()


def test_a_write_is_refused_if_the_file_changed(tmp_path: Path) -> None:
    (tmp_path / "AGENTS.md").write_text("mine\n", encoding="utf-8")
    with pytest.raises(UsageError, match="changed"):
        write_repo_bytes(tmp_path, "AGENTS.md", b"new\n", expected=b"older\n")
    assert (tmp_path / "AGENTS.md").read_text(encoding="utf-8") == "mine\n"


def test_a_write_keeps_the_mode_and_leaves_no_temp_file(tmp_path: Path) -> None:
    target = tmp_path / "AGENTS.md"
    target.write_text("old\n", encoding="utf-8")
    target.chmod(0o600)
    write_repo_bytes(tmp_path, "AGENTS.md", b"new\n", expected=b"old\n")
    assert target.read_bytes() == b"new\n"
    assert stat.S_IMODE(target.stat().st_mode) == 0o600
    assert sorted(p.name for p in tmp_path.iterdir()) == ["AGENTS.md"]


@pytest.mark.parametrize("relpath", ["", "../x", "a//b", "./a"])
def test_odd_relative_paths_are_refused(tmp_path: Path, relpath: str) -> None:
    with pytest.raises(UsageError):
        read_repo_bytes(tmp_path, relpath)


def test_oversized_files_are_refused(tmp_path: Path) -> None:
    (tmp_path / "AGENTS.md").write_bytes(b"x" * 20)
    with pytest.raises(UsageError, match="larger"):
        read_repo_bytes(tmp_path, "AGENTS.md", limit=10)
