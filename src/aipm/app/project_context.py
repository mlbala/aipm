"""The `ProjectContext` that `prompt` and `sync-context` render from (ARCHITECTURE §10).

Built from the state snapshot and the loaded config; nothing here calls an LLM. Gate argv is
compiled here, through `compile_gate`, with the placeholders as an agent sees them (ADR-0017):

- `{paths}` expands to nothing, so the tool checks the whole project, as `aipm trust` shows it;
- `{test_paths}` expands to the first test root;
- `{report_file}` is `/dev/null`: only aipm's own gate run reads a report, from a path it
  generates for that run (§13.1), so an agent's copy has nowhere useful to go.

Callers check trust before they show or write anything built from this (SECURITY.md §6 rule 3).
"""

from pathlib import Path

from aipm.config.schema import Config
from aipm.domain.errors import PolicyViolation, UsageError
from aipm.domain.models import (
    ComponentInfo,
    FeatureInfo,
    GateCommand,
    ProjectContext,
    StateSnapshot,
)
from aipm.security.command_policy import CommandPolicy, compile_gate
from aipm.security.paths import protected_patterns

AGENT_REPORT_FILE = Path("/dev/null")


def agent_gates(cfg: Config, *, detail: bool = True) -> tuple[GateCommand, ...]:
    """Every gate of the menu: command gates with argv from `compile_gate`, built-ins by name.

    Raises `PolicyViolation` (exit 6) if any argv fails the command policy. With
    `detail=False` (`sync-context --check`, which runs without trust) the error names only the
    gate, never a piece of its argv.
    """
    gates: list[GateCommand] = []
    policy: CommandPolicy | None = None
    for name, gate in sorted(cfg.gates.items()):
        if gate.run is None:
            builtin = None if gate.builtin is None else gate.builtin.value
            gates.append(GateCommand(name, gate.required, builtin=builtin))
            continue
        try:
            if policy is None:
                policy = cfg.command_policy()
            argv = compile_gate(gate, paths=[], policy=policy, report_file=AGENT_REPORT_FILE)
        except PolicyViolation as exc:
            if detail:
                raise PolicyViolation(f"gate {name!r}: {exc.message}", hint=exc.hint) from None
            raise PolicyViolation(
                f"gate {name!r} is not allowed by the command policy",
                hint="Run `aipm trust --show` to see why.",
            ) from None
        gates.append(GateCommand(name, gate.required, argv=argv))
    return tuple(gates)


def build_context(snapshot: StateSnapshot, cfg: Config, *, detail: bool = True) -> ProjectContext:
    """The approved facts and the agent-facing gate menu. The caller checked the inputs."""
    requirements, prd, arch = snapshot.requirements, snapshot.prd, snapshot.architecture
    if requirements is None or prd is None or arch is None:
        raise UsageError("the approved PRD and design are needed first", hint="Run `aipm design`.")
    stack = tuple((k, v) for k, v in arch.meta.stack.model_dump(mode="json").items() if v)
    return ProjectContext(
        project=requirements.project.name,
        mode=requirements.mode.value,
        one_liner=requirements.project.one_liner,
        features=tuple(FeatureInfo(f.id, f.priority.value, f.title) for f in prd.meta.features),
        stack=stack,
        stack_template=arch.meta.stack_template,
        components=tuple(
            ComponentInfo(c.id, c.name, tuple(c.paths), c.responsibility)
            for c in arch.meta.components
        ),
        gates=agent_gates(cfg, detail=detail),
        test_roots=tuple(cfg.test_roots),
        protected_paths=protected_patterns(cfg.security.extra_protected_paths),
        new_dependencies=cfg.security.allow_new_dependencies.value,
        agent_network=cfg.security.network.agent.value,
        allowed_url_domains=tuple(cfg.context.allowed_url_domains),
        tasks=tuple(snapshot.tasks.tasks) if snapshot.tasks is not None else (),
    )
