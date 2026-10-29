"""Prompt compiler: the canonical `TaskSpec`, assembled deterministically from `tasks.yaml`, the
approved design and the trusted config, with no LLM involved (ARCHITECTURE §10.1).

- `verify[]` holds the command gates the task names plus every required gate, in the order
  `verify` runs them, with argv that already passed `compile_gate` (`ProjectContext.gates`).
  A gate the task names that the menu no longer defines stops the compile (exit 2).
- The task's title, description and criteria, and its upstream titles, are model text approved
  at G3: each field is cleaned with `sanitize_for_context` and carried as `Untrusted`.
- For a fix prompt, `previous_attempt` holds each failing gate's summary and output, cleaned,
  cut to its first and last 4 KiB, and wrapped as `Untrusted` (SECURITY.md §7.1).

`render_within_budget` keeps the rendered prompt within 24 KiB. Over budget it drops, in order,
the read-only file list, the upstream titles, and then more of the previous output. A prompt
still over budget is refused (exit 2) rather than cut silently.
"""

from collections.abc import Sequence
from dataclasses import replace

from aipm.adapters.base import RenderedTaskPrompt, ToolAdapter
from aipm.context.generator import clean, gate_order
from aipm.domain.errors import UsageError
from aipm.domain.models import (
    GateCommand,
    GateFailure,
    GateReport,
    GateResult,
    ProjectContext,
    Task,
    TaskSpec,
    UpstreamTask,
)
from aipm.security.sanitize import head_tail
from aipm.security.untrusted import Untrusted

MAX_PROMPT_BYTES = 24 * 1024
GATE_OUTPUT_BYTES = 4096
"""Head and tail kept from each failing gate's output (SECURITY.md §7.1)."""
SHRINK_STEPS = (2048, 1024, 512)


class PromptTooLarge(UsageError):
    """The task prompt is over its budget even after trimming."""

    code = "PROMPT_TOO_LARGE"


def task_text(task: Task, allowed_url_domains: Sequence[str]) -> Untrusted:
    """The task's own words: title, description and acceptance criteria, as one block."""
    lines = [f"Title: {clean(task.title, allowed_url_domains)}"]
    if task.description.strip():
        lines += ["", "Description:", clean(task.description, allowed_url_domains)]
    lines += ["", "Acceptance criteria:"]
    lines += [f"- {c.id}: {clean(c.text, allowed_url_domains)}" for c in task.acceptance]
    return Untrusted("\n".join(lines), source=f"approved:tasks.yaml#{task.id}")


def _gates(task: Task, ctx: ProjectContext) -> tuple[list[GateCommand], list[GateCommand]]:
    menu = {g.name for g in ctx.gates}
    unknown = sorted(set(task.gates) - menu)
    if unknown:
        raise UsageError(
            f"{task.id} uses gates that .pm/config.yaml no longer defines: {', '.join(unknown)}",
            hint="Restore them in the gate menu, or run `aipm plan` again.",
        )
    wanted = set(task.gates)
    chosen = [g for g in gate_order(ctx.gates) if g.name in wanted or g.required]
    return [g for g in chosen if g.argv is not None], [g for g in chosen if g.argv is None]


def _upstream(task: Task, ctx: ProjectContext) -> tuple[UpstreamTask, ...]:
    by_id = {t.id: t for t in ctx.tasks}
    found: list[UpstreamTask] = []
    for dep in task.depends_on:
        other = by_id.get(dep)
        if other is None:
            continue
        found.append(
            UpstreamTask(
                id=dep,
                status=other.status.value,
                commit=other.done.commit if other.done is not None else None,
                title=Untrusted(
                    clean(other.title, ctx.allowed_url_domains), source=f"approved:tasks.yaml#{dep}"
                ),
            )
        )
    return tuple(found)


def _failure_text(result: GateResult, allowed_url_domains: Sequence[str], size: int) -> str:
    raw = "\n\n".join(p.strip("\n") for p in (result.summary, result.output) if p.strip())
    return head_tail(clean(raw, allowed_url_domains), size, size) or "(no output)"


def previous_attempt(
    report: GateReport, allowed_url_domains: Sequence[str], *, size: int = GATE_OUTPUT_BYTES
) -> tuple[GateFailure, ...]:
    """Each failing gate's output, cleaned, cut to head and tail, and wrapped as untrusted."""
    return tuple(
        GateFailure(
            gate=g.name,
            status=g.status.value,
            output=Untrusted(
                _failure_text(g, allowed_url_domains, size), source=f"gate-output:{g.name}"
            ),
        )
        for g in report.failures()
    )


def compile_task_spec(
    task: Task, ctx: ProjectContext, *, previous: GateReport | None = None
) -> TaskSpec:
    """Assemble the task spec; gate argv comes only from `ctx.gates` (`compile_gate` output)."""
    allowed = ctx.allowed_url_domains
    verify, builtins = _gates(task, ctx)
    failures = previous_attempt(previous, allowed) if previous is not None else ()
    return TaskSpec(
        id=task.id,
        project=ctx.project,
        type=task.type.value,
        size=task.size.value,
        text=task_text(task, allowed),
        acceptance_ids=tuple(c.id for c in task.acceptance),
        owns_files=tuple(task.owns_files),
        reads_files=tuple(task.reads_files),
        deps_add=tuple((d.ecosystem.value, d.name) for d in task.deps_add),
        upstream=_upstream(task, ctx),
        verify=tuple(verify),
        builtin_gates=tuple(builtins),
        protected_paths=ctx.protected_paths,
        new_dependencies=ctx.new_dependencies,
        agent_network=ctx.agent_network,
        previous_attempt=failures,
        fix=previous is not None,
    )


def _trimmed(spec: TaskSpec) -> list[TaskSpec]:
    """`spec`, then each smaller version, in the order ARCHITECTURE §10.1 trims."""
    steps = [spec]
    current = spec
    if current.reads_files:
        current = replace(
            current, reads_files=(), omitted=(*current.omitted, "the read-only file list")
        )
        steps.append(current)
    if any(u.title is not None for u in current.upstream):
        current = replace(
            current,
            upstream=tuple(replace(u, title=None) for u in current.upstream),
            omitted=(*current.omitted, "the titles of upstream tasks"),
        )
        steps.append(current)
    if current.previous_attempt:
        base = current
        for size in SHRINK_STEPS:
            shrunk = tuple(
                replace(
                    f,
                    output=Untrusted(head_tail(f.output.text, size, size), source=f.output.source),
                )
                for f in spec.previous_attempt
            )
            steps.append(
                replace(
                    base,
                    previous_attempt=shrunk,
                    omitted=(*base.omitted, "most of the earlier check output"),
                )
            )
    return steps


def render_within_budget(
    adapter: ToolAdapter, spec: TaskSpec, ctx: ProjectContext, *, budget: int = MAX_PROMPT_BYTES
) -> RenderedTaskPrompt:
    """Render the smallest needed version of `spec` that fits `budget` bytes; exit 2 if none."""
    smallest = 0
    for candidate in _trimmed(spec):
        rendered = adapter.render_prompt(candidate, ctx)
        if rendered.size <= budget:
            return rendered
        smallest = rendered.size
    raise PromptTooLarge(
        f"the prompt for {spec.id} is {smallest} bytes even after trimming; the budget is "
        f"{budget} bytes",
        hint="Split the task, or shorten its description and criteria, then run `aipm plan`.",
    )


__all__ = [
    "MAX_PROMPT_BYTES",
    "PromptTooLarge",
    "compile_task_spec",
    "previous_attempt",
    "render_within_budget",
    "task_text",
]
