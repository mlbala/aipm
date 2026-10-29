"""Checks shared by the commands that call LLM roles (SECURITY.md §7.9, §7.3).

`check_injection` records a role's `injection_suspected` report as a security event before
anything from that reply is used, then asks an interactive user, or stops a non-interactive run
(exit 4) unless `--accept-risk` was given. `with_repair` gives a role one more try when
deterministic checks reject its reply; the problems it passes back are aipm's own words, wrapped
as `Untrusted`.
"""

from collections.abc import Callable, Sequence
from dataclasses import dataclass

from pydantic import BaseModel

from aipm.domain.errors import HumanInputRequired
from aipm.domain.models import RoleName, SecurityEventKind
from aipm.llm.gateway import Gateway, RenderedPrompt, TokenBudget
from aipm.security.untrusted import Untrusted
from aipm.state.store import FileStateStore

REPAIR_SOURCE = "aipm:validator"


class InjectionSuspected(HumanInputRequired):
    """A role reported suspected prompt injection and the run may not continue (exit 4)."""

    code = "INJECTION_SUSPECTED"


type ConfirmRisk = Callable[[str, Sequence[str]], bool]


def check_injection(
    store: FileStateStore,
    role: RoleName,
    excerpts: Sequence[str],
    *,
    confirm: ConfirmRisk | None,
    accept_risk: bool,
    warnings: list[str],
) -> None:
    """Record and act on `injection_suspected`; `confirm` is the interactive prompt, if any."""
    if not excerpts:
        return
    items = [e for e in excerpts if e.strip()] or ["(no excerpt given)"]
    store.append_event(
        SecurityEventKind.INJECTION_SIGNAL,
        source=f"llm:{role.value}",
        detail=f"the {role.value} reported {len(items)} suspected instructions in its input",
        data={"excerpts": list(items)},
    )
    data: dict[str, object] = {"role": role.value, "injection_suspected": list(items)}
    if confirm is not None:
        if not confirm(role.value, items):
            raise InjectionSuspected("stopped after suspected prompt injection", data=data)
        return
    if not accept_risk:
        raise InjectionSuspected(
            f"the {role.value} reported suspected prompt injection in its input",
            hint="Review the input. To continue anyway, run again with --accept-risk.",
            data=data,
        )
    warnings.append(
        f"--accept-risk: the {role.value} reported suspected prompt injection: " + " | ".join(items)
    )


def repair_block(problems: Sequence[str]) -> Untrusted:
    """The problems for a repair attempt, as one `Untrusted` block."""
    return Untrusted("\n".join(f"- {p}" for p in problems), source=REPAIR_SOURCE)


@dataclass(frozen=True, slots=True)
class Attempt[T]:
    """One validated reply and the problems deterministic checks found in it."""

    value: T
    problems: tuple[str, ...]


def with_repair[T: BaseModel](
    gateway: Gateway,
    role: RoleName,
    schema: type[T],
    *,
    render: Callable[[Untrusted | None], RenderedPrompt],
    check: Callable[[T], Sequence[str]],
    budget: Callable[[], TokenBudget],
    on_reply: Callable[[T], None],
) -> Attempt[T]:
    """Run a role; if `check` finds problems, run it once more with them. `on_reply` sees every
    reply first (the injection check), so nothing from a flagged reply is ever used."""
    first = gateway.run(role, render(None), schema, budget=budget()).value
    on_reply(first)
    problems = tuple(check(first))
    if not problems:
        return Attempt(first, ())
    second = gateway.run(role, render(repair_block(problems)), schema, budget=budget()).value
    on_reply(second)
    return Attempt(second, tuple(check(second)))
