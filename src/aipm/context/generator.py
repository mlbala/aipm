"""Context files: `AGENTS.md` and `CLAUDE.md` in v0.1 (ARCHITECTURE §10.2).

A context file persists across every future agent session, so a poisoned one is a persistent
prompt injection. Each managed block is rendered only from aipm's package templates and the
approved, structured facts in `ProjectContext`:

- every interpolated field goes through `sanitize_for_context` (L1, HTML comments and URLs
  outside `context.allowed_url_domains` removed, `@` mentions neutralized);
- model-written text (the one-liner, feature titles, component names and responsibilities) is
  rendered only inside fenced `untrusted` blocks; IDs, stack names, globs and gate argv, which are
  validated by pattern or by `compile_gate`, go in code spans, and paths and globs must be
  plain (letters, digits and `. _ / * ? + -`) or the command refuses (exit 6);
- gate argv comes only from `compile_gate` output, which the caller produces only when the
  execution surface is trusted (SECURITY.md §6 rule 3); argv that sanitizing would change is
  refused rather than shown altered;
- the finished block is checked against invariant I-3 and refused (exit 6) if it fails.

The `AGENTS.md` block is at most 24 KiB: component descriptions go first, then the feature list.
"""

import re
import shlex
from collections.abc import Callable, Iterable, Mapping
from typing import cast

from aipm import context as _package
from aipm.context.markdown import (
    ContentNonces,
    agent_text_problems,
    code_span,
    fence,
    seed_of,
)
from aipm.domain.errors import PolicyViolation, UsageError
from aipm.domain.models import GateCommand, GeneratedFile, ProjectContext
from aipm.security.agent_text import is_plain_path
from aipm.security.sanitize import sanitize_for_context
from aipm.security.untrusted import PackageTemplateLoader, Untrusted, make_env

AGENTS_FILE = "AGENTS.md"
CLAUDE_FILE = "CLAUDE.md"
CONTEXT_FILES = (AGENTS_FILE, CLAUDE_FILE)
"""The only repository files outside `.pm/` that hold a managed block in v0.1."""
CLAUDE_IMPORT = "@AGENTS.md"
MAX_BLOCK_BYTES = 24 * 1024

GATE_ORDER = ("secrets", "lint", "format", "types", "unit", "ac_trace", "sast", "deps", "ac_review")
"""ARCHITECTURE §13.2: cheap gates first."""

BUILTIN_CHECKS: Mapping[str, str] = {
    "gitleaks": "aipm scans the change for secrets (gitleaks)",
    "semgrep": "aipm runs static analysis (semgrep) on the files the task owns",
    "osv": "aipm checks new dependencies against the task's `deps_add`, their registry and "
    "known vulnerabilities (osv-scanner)",
    "ac_trace": "every acceptance criterion ID of the task must appear in a test that ran in the "
    "unit tests",
    "ac_review": "a reviewer model compares each acceptance criterion with the change; it can "
    "fail a task, never pass one",
}

DEPENDENCY_RULES: Mapping[str, str] = {
    "deny": "MUST NOT add any dependency.",
    "ask": "MUST NOT add a dependency that your task does not declare in `deps_add`.",
    "allow": "MUST NOT add a dependency that your task does not declare in `deps_add`.",
}
"""`security.allow_new_dependencies` as a rule; an unknown value gets the strictest one."""
NETWORK_RULES: Mapping[str, str] = {
    "none": "MUST NOT use the network.",
    "api-only": "MUST NOT use the network, except your own coding tool's API.",
    "registries": "MUST NOT use the network, except package registries.",
}
"""`security.network.agent` as a rule; an unknown value gets the strictest one."""

_BLANK_RUNS = re.compile(r"\n{3,}")


class ContextTooLarge(UsageError):
    """A managed block is over its size budget even after trimming."""

    code = "CONTEXT_TOO_LARGE"


def gate_order(gates: Iterable[GateCommand]) -> list[GateCommand]:
    """Gates in the order `verify` runs them; unknown names last, by name."""
    rank = {name: i for i, name in enumerate(GATE_ORDER)}
    return sorted(gates, key=lambda g: (rank.get(g.name, len(rank)), g.name))


def clean(text: str, allowed_url_domains: Iterable[str]) -> str:
    """One field, ready for a context file or task prompt."""
    return sanitize_for_context(text, allowed_url_domains=allowed_url_domains).text


def literal(value: str, allowed_url_domains: Iterable[str], *, what: str) -> str:
    """A validated value (argv element, glob, ID) for a code span, which is never altered.

    If sanitizing would change it (a URL, an HTML comment, an invisible character), it is
    refused: showing an agent a command or path that differs from the real one is worse.
    """
    removed = sanitize_for_context(value, allowed_url_domains=allowed_url_domains).removed
    if any(kind != "mention" for kind in removed):
        raise PolicyViolation(
            f"{what} holds text that context files never carry ({', '.join(sorted(removed))})",
            hint="Change it in .pm/config.yaml or the plan, then run aipm again.",
        )
    return value


def path_literal(value: str, *, what: str) -> str:
    """A path or glob for a code span: plain characters only, or refused (exit 6).

    Globs from the plan and protected paths from the config can hold up to 512 characters;
    allowing only `A-Z a-z 0-9 . _ / * ? + -` means none of them can carry a sentence, a quote
    or an `@` mention into the rules an agent reads (SECURITY.md §7.10).
    """
    if not is_plain_path(value):
        raise PolicyViolation(
            f"{what} {value[:60]!r} holds characters aipm never shows an agent in a path "
            "(only letters, digits and . _ / * ? + - are allowed)",
            hint="Rename the path in the plan, the design or .pm/config.yaml, then run aipm again.",
        )
    return value


def command_line(gate: GateCommand, allowed_url_domains: Iterable[str]) -> str:
    """A command gate's argv as one shell-quoted code span."""
    if gate.argv is None:
        raise PolicyViolation(f"gate {gate.name!r} has no argv")
    args = [literal(a, allowed_url_domains, what=f"gate {gate.name!r}") for a in gate.argv]
    return code_span(shlex.join(args))


def render(template: str, data: Mapping[str, object], *, seed_parts: Iterable[str]) -> str:
    """Render a package template with content-derived nonces and tidy blank lines."""
    env = make_env(
        PackageTemplateLoader(_package, "templates"), nonce=ContentNonces(seed_of(seed_parts))
    )
    filters = cast("dict[str, Callable[..., object]]", env.filters)  # pyright: ignore[reportUnknownMemberType]
    filters["fence"] = fence
    text = env.get_template(template).render(**data)
    return _BLANK_RUNS.sub("\n\n", text).strip("\n") + "\n"


def _checked(name: str, block: str, ctx: ProjectContext, imports: Iterable[str] = ()) -> str:
    problems = agent_text_problems(
        block, allowed_url_domains=ctx.allowed_url_domains, imports=imports
    )
    if problems:
        raise PolicyViolation(
            f"the generated {name} block fails invariant I-3: {'; '.join(problems)}",
            hint="This is a bug in aipm; nothing was written. Please report it.",
        )
    size = len(block.encode("utf-8"))
    if size > MAX_BLOCK_BYTES:
        raise ContextTooLarge(
            f"the generated {name} block is {size} bytes, over the {MAX_BLOCK_BYTES}-byte budget",
            hint="Shorten the architecture's component list or the PRD's features.",
        )
    return block


# ---------------------------------------------------------------- AGENTS.md


def _overview(ctx: ProjectContext, *, features: bool) -> Untrusted | None:
    allowed = ctx.allowed_url_domains
    lines: list[str] = []
    if ctx.one_liner.strip():
        lines.append(clean(ctx.one_liner, allowed))
    if features and ctx.features:
        lines.append("Features:")
        lines.extend(f"- {f.id} ({f.priority}): {clean(f.title, allowed)}" for f in ctx.features)
    return Untrusted(clean("\n".join(lines), allowed), source="approved:prd") if lines else None


def _components(ctx: ProjectContext) -> Untrusted | None:
    allowed = ctx.allowed_url_domains
    lines = [
        f"- {c.id} {clean(c.name, allowed)}"
        + (f": {clean(c.responsibility, allowed)}" if c.responsibility.strip() else "")
        for c in ctx.components
    ]
    if not lines:
        return None
    # Joined fields can form a new URL ("<name>: " can read as "data: "), so clean the whole.
    return Untrusted(clean("\n".join(lines), allowed), source="approved:architecture")


def _agents_data(ctx: ProjectContext, *, features: bool, descriptions: bool) -> dict[str, object]:
    allowed = ctx.allowed_url_domains
    ordered = gate_order(ctx.gates)
    return {
        "project": code_span(literal(ctx.project, allowed, what="the project name")),
        "mode": ctx.mode,
        "overview": _overview(ctx, features=features),
        "feature_ids": [f.id for f in ctx.features],
        "stack": [
            (k.replace("_", " "), code_span(literal(v, allowed, what="the stack")))
            for k, v in ctx.stack
        ],
        "stack_template": None if ctx.stack_template is None else code_span(ctx.stack_template),
        "checks": [
            {"name": g.name, "required": g.required, "command": command_line(g, allowed)}
            for g in ordered
            if g.argv is not None
        ],
        "builtins": [
            {
                "name": g.name,
                "required": g.required,
                "what": BUILTIN_CHECKS.get(g.builtin or "", "a built-in check"),
            }
            for g in ordered
            if g.argv is None
        ],
        "components": [
            {
                "id": c.id,
                "paths": [
                    code_span(path_literal(p, what=f"a path of component {c.id}")) for p in c.paths
                ],
            }
            for c in ctx.components
        ],
        "component_text": _components(ctx) if descriptions else None,
        "omitted": [
            name
            for name, kept in (
                ("component descriptions", descriptions),
                ("the feature list", features),
            )
            if not kept
        ],
        "test_roots": [code_span(path_literal(r, what="a test root")) for r in ctx.test_roots],
        "protected": [
            code_span(path_literal(p, what="a protected path")) for p in ctx.protected_paths
        ],
        "dependency_rule": DEPENDENCY_RULES.get(ctx.new_dependencies, DEPENDENCY_RULES["deny"]),
        "network_rule": NETWORK_RULES.get(ctx.agent_network, NETWORK_RULES["none"]),
    }


def _seed(ctx: ProjectContext) -> list[str]:
    parts = [ctx.project, ctx.mode, ctx.one_liner]
    parts += [f"{f.id}|{f.priority}|{f.title}" for f in ctx.features]
    parts += [f"{c.id}|{c.name}|{c.responsibility}|{'|'.join(c.paths)}" for c in ctx.components]
    return parts


def agents_md(ctx: ProjectContext) -> GeneratedFile:
    """The `AGENTS.md` managed block, trimmed to its budget if needed."""
    for features, descriptions in ((True, True), (True, False), (False, False)):
        block = render(
            "agents.md.j2",
            _agents_data(ctx, features=features, descriptions=descriptions),
            seed_parts=_seed(ctx),
        )
        if len(block.encode("utf-8")) <= MAX_BLOCK_BYTES:
            break
    return GeneratedFile(AGENTS_FILE, _checked(AGENTS_FILE, block, ctx))


# ---------------------------------------------------------------- CLAUDE.md


def claude_md(ctx: ProjectContext) -> GeneratedFile:
    """The `CLAUDE.md` managed block: the `@AGENTS.md` import plus Claude Code notes."""
    block = render("claude.md.j2", {"import_line": CLAUDE_IMPORT}, seed_parts=[ctx.project])
    return GeneratedFile(CLAUDE_FILE, _checked(CLAUDE_FILE, block, ctx, imports=[CLAUDE_IMPORT]))


def generate(ctx: ProjectContext) -> list[GeneratedFile]:
    """Render `AGENTS.md` and `CLAUDE.md` from approved, sanitized fields."""
    return [agents_md(ctx), claude_md(ctx)]


# ---------------------------------------------------------------- Claude subagents and skills


def _front_matter(name: str, description: str, tools: str | None = None) -> str:
    lines = ["---", f"name: {name}", f"description: {description}"]
    if tools is not None:
        lines.append(f"tools: {tools}")
    return "\n".join([*lines, "---", "", ""])


CLAUDE_EXTRAS: Mapping[str, tuple[str, str]] = {
    ".claude/agents/aipm-test-writer.md": (
        "aipm-test-writer.md.j2",
        _front_matter(
            "aipm-test-writer",
            "Writes the tests for an aipm task, one or more per acceptance criterion, only under "
            "the paths the task owns. Use it when a task prompt asks for tests.",
            "Read, Grep, Glob, Edit, Write, Bash",
        ),
    ),
    ".claude/agents/aipm-reviewer.md": (
        "aipm-reviewer.md.j2",
        _front_matter(
            "aipm-reviewer",
            "Reviews an aipm task's change against its acceptance criteria, the files it owns "
            "and the protected paths, before aipm verify. Read-only.",
            "Read, Grep, Glob",
        ),
    ),
    ".claude/skills/aipm-task-protocol/SKILL.md": (
        "aipm-task-protocol.md.j2",
        _front_matter(
            "aipm-task-protocol",
            "The rules for working on an aipm task (T-ID): owned files, protected paths, "
            "dependencies, tests that carry acceptance-criterion IDs, and how to say you are "
            "blocked.",
        ),
    ),
    ".claude/skills/aipm-run-checks/SKILL.md": (
        "aipm-run-checks.md.j2",
        _front_matter(
            "aipm-run-checks",
            "The exact commands that check an aipm task before you finish it, as aipm verify "
            "runs them.",
        ),
    ),
}
"""aipm's own Claude Code subagents and skills (ARCHITECTURE §10.2, v0.2): fixed front matter
(no `allowed-tools`; the reviewer reads only), instructions only, never a script."""

TEST_CONFIG_NAMES = ("pytest.ini", "conftest.py", "tox.ini", "setup.cfg", ".coveragerc",
                     "jest.config.*", "vitest.config.*")  # fmt: skip


def claude_extras(ctx: ProjectContext) -> list[GeneratedFile]:
    """The Claude Code subagents and skills, rendered like `AGENTS.md` and checked for I-3."""
    data = _agents_data(ctx, features=False, descriptions=False)
    data["test_config"] = [code_span(name) for name in TEST_CONFIG_NAMES]
    files: list[GeneratedFile] = []
    for path, (template, preamble) in CLAUDE_EXTRAS.items():
        block = render(template, data, seed_parts=[ctx.project, path])
        _checked(path, preamble, ctx)
        files.append(GeneratedFile(path, _checked(path, block, ctx), preamble=preamble))
    return files
