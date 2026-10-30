"""`aipm design`: architecture, ADRs and threat model, then G2 (ARCHITECTURE §7.2, §14.1).

The PRD must be approved (G1) and current, unless `--accept-stale`, which is recorded in
`approvals.yaml`. Either way it reaches the architect wrapped as `Untrusted`, labelled
`approved:prd`, `unapproved:prd` or `stale:prd`. The threat modeler reads the architecture the
architect just drafted, as `unapproved:architecture`, and the hash it records is the hash of the
exact bytes the store will write.

Both roles get one repair attempt when aipm's checks reject a reply (stack template not built
in, unsafe component path, unknown component, missing OWASP LLM item); after that the command
exits 1 and nothing is written. Nothing is written until both roles pass.

A current design is not regenerated without `--regenerate`, and a stale one needs
`--regenerate`, so hand edits are never overwritten silently.
"""

from collections.abc import Sequence
from dataclasses import dataclass, field
from pathlib import Path
from typing import Protocol

from aipm.app import runtime
from aipm.app.approve import (
    DesignReview,
    design_review_of,
    record_design,
    require_inputs,
)
from aipm.app.guards import check_injection, with_repair
from aipm.app.snapshot import read_snapshot
from aipm.app.workspace import find_repo_root, require_initialized
from aipm.config.loader import load_config
from aipm.config.schema import Config
from aipm.config.stacks import available_stacks
from aipm.domain.errors import AipmError, UsageError
from aipm.domain.models import (
    ArchitectureDoc,
    ArtifactKind,
    Mode,
    RepoMapDoc,
    RoleName,
    StateSnapshot,
)
from aipm.domain.phase import InputCheck, InputState, design_inputs, plan_inputs
from aipm.llm.cost import UsageLedger
from aipm.llm.gateway import Gateway, RenderedPrompt, TokenBudget, open_gateway
from aipm.roles import architect, threat_modeler
from aipm.roles.architect import ArchitectureDraft
from aipm.roles.threat_modeler import ThreatModelDraft
from aipm.security.untrusted import Untrusted
from aipm.state.store import FileStateStore, normalized_sha256, open_store


class DesignRejected(AipmError):
    """A design role's reply still failed aipm's checks after one repair attempt (exit 1)."""

    code = "DESIGN_REJECTED"


class DesignPrompter(Protocol):
    """The interactive side of `aipm design`, implemented by the CLI."""

    def confirm_risk(self, role: str, excerpts: Sequence[str]) -> bool:
        """Warn about suspected prompt injection; True continues."""
        ...

    def approve_design(self, review: DesignReview) -> bool:
        """G2: show the stack, components, ADR titles and threats, then ask."""
        ...


@dataclass(frozen=True, slots=True)
class DesignOptions:
    """The command's flags."""

    regenerate: bool = False
    accept_risk: bool = False
    accept_stale: bool = False
    yes: bool = False


@dataclass(frozen=True, slots=True)
class DesignResult:
    """What `aipm design` did, for the CLI to report."""

    repo_root: str
    generated: bool
    written: tuple[str, ...]
    approval: str
    stack_copied: bool
    review: DesignReview
    usage: dict[str, object]
    warnings: tuple[str, ...]
    notes: tuple[str, ...]

    def to_data(self) -> dict[str, object]:
        """The `--json` payload."""
        return {
            "repo": self.repo_root,
            "generated": self.generated,
            "written": list(self.written),
            "approval": self.approval,
            "stack_copied": self.stack_copied,
            "design": self.review.to_data(),
            "usage": self.usage,
            "warnings": list(self.warnings),
            "notes": list(self.notes),
        }


def run(
    project: Path | None, *, options: DesignOptions, prompter: DesignPrompter | None
) -> DesignResult:
    """Run the use case. `prompter` is None in a non-interactive run."""
    root = find_repo_root(project)
    require_initialized(root)
    loaded = load_config(root)
    redactor = runtime.user_redactor(root)
    store = open_store(root, redactor=redactor)
    with store.lock():
        snapshot, _ = read_snapshot(
            store, coverage_threshold=loaded.config.discover.coverage_threshold, trusted=False
        )
        checks = design_inputs(snapshot)
        warnings = list(loaded.warnings)
        warnings += require_inputs(store, "design", checks, accept_stale=options.accept_stale)
        session = _Design(
            root=root,
            cfg=loaded.config,
            store=store,
            prompter=prompter,
            options=options,
            snapshot=snapshot,
            prd=checks[0],
            warnings=warnings,
        )
        return session.run()


@dataclass
class _Design:
    root: Path
    cfg: Config
    store: FileStateStore
    prompter: DesignPrompter | None
    options: DesignOptions
    snapshot: StateSnapshot
    prd: InputCheck
    warnings: list[str]
    notes: list[str] = field(default_factory=list[str])
    ledger: UsageLedger = field(default_factory=UsageLedger)
    _gateway: Gateway | None = None

    @property
    def project(self) -> str:
        reqs = self.snapshot.requirements
        return reqs.project.name if reqs is not None else (self.cfg.project.name or "project")

    def run(self) -> DesignResult:
        generated = self._needs_generation()
        written: tuple[str, ...] = ()
        if generated:
            written = self._generate()
        review = design_review_of(self.store)
        approval, copied = self._g2(review)
        if copied:
            self.notes.append(
                f"copied the {review.stack_template} stack's prepare step, gates and allowed "
                "commands into .pm/config.yaml; the execution surface changed, so run `aipm trust` "
                "after reviewing it"
            )
            written += ("config.yaml",)
        if approval == "approved":
            written += ("approvals.yaml",)
        return DesignResult(
            repo_root=str(self.root),
            generated=generated,
            written=written,
            approval=approval,
            stack_copied=copied,
            review=review,
            usage=self.ledger.to_data(),
            warnings=tuple(self.warnings),
            notes=tuple(self.notes),
        )

    # ------------------------------------------------------------ whether to call the roles

    def _needs_generation(self) -> bool:
        s = self.snapshot
        if s.architecture is None or self.options.regenerate:
            return True
        _, arch, tm, _ = plan_inputs(s)
        bad = [c.reason for c in (arch, tm) if c.state in (InputState.STALE, InputState.MISSING)]
        if bad:
            raise UsageError(
                "the design is stale or incomplete: " + "; ".join(bad),
                hint="Run `aipm design --regenerate` to rebuild it from the current PRD.",
            )
        self.notes.append("the design is current; pass --regenerate to rebuild it")
        return False

    # ------------------------------------------------------------ the two roles

    def _gateway_for(self) -> Gateway:
        if self._gateway is None:
            self._gateway = open_gateway(
                self.cfg.llm, redactor=self.store.redactor, ledger=self.ledger
            )
        return self._gateway

    def _budget(self) -> TokenBudget:
        return TokenBudget(self.cfg.budget.run_tokens - self.ledger.total_tokens)

    def _check(self, role: RoleName, excerpts: Sequence[str]) -> None:
        confirm = self.prompter.confirm_risk if self.prompter is not None else None
        check_injection(self.store, role, excerpts, confirm=confirm,
                        accept_risk=self.options.accept_risk, warnings=self.warnings)  # fmt: skip

    def _prd_text(self) -> tuple[Untrusted, str]:
        text = self.store.read_text(ArtifactKind.PRD)
        if text is None:  # pragma: no cover - checked by design_inputs
            raise UsageError("prd.md is missing", hint="Run `aipm discover` first.")
        sha = normalized_sha256(text.encode("utf-8"))
        if sha != self.prd.sha256:
            raise UsageError("prd.md changed while aipm was reading it; nothing was written")
        return Untrusted(text, source=self.prd.label), sha

    def _repo_map(self) -> Untrusted | None:
        reqs = self.snapshot.requirements
        if reqs is None or reqs.mode is not Mode.BROWNFIELD:
            return None
        if not self.store.exists(ArtifactKind.REPO_MAP):
            return None
        doc = self.store.load(ArtifactKind.REPO_MAP)
        return Untrusted(doc.body, source="repo-map.md") if isinstance(doc, RepoMapDoc) else None

    def _architect(self, prd: Untrusted) -> ArchitectureDraft:
        role = architect.create()
        stacks = tuple(available_stacks())
        reqs = self.snapshot.requirements
        mode = reqs.mode.value if reqs is not None else Mode.GREENFIELD.value
        repo_map = self._repo_map()

        def render(problems: Untrusted | None) -> RenderedPrompt:
            return role.render(architect.ArchitectInput(
                project=self.project, mode=mode, prd=prd, stacks=stacks, repo_map=repo_map,
                problems=problems))  # fmt: skip

        attempt = with_repair(
            self._gateway_for(),
            RoleName.ARCHITECT,
            ArchitectureDraft,
            render=render,
            check=lambda out: architect.problems(out, stacks),
            budget=self._budget,
            on_reply=lambda out: self._check(RoleName.ARCHITECT, out.injection_suspected),
        )
        if attempt.problems:
            raise DesignRejected(
                "the architect's reply failed aipm's checks twice, so nothing was written",
                hint="Run `aipm design --regenerate` again, or try a stronger model.",
                data={"role": "architect", "problems": list(attempt.problems)},
            )
        inp = architect.ArchitectInput(project=self.project, mode=mode, prd=prd, stacks=stacks)
        return role.postprocess(attempt.value, inp)

    def _threat_model(self, draft: ArchitectureDraft, text: str) -> ThreatModelDraft:
        role = threat_modeler.create()
        components = tuple(c.id for c in draft.components)
        doc = Untrusted(text, source="unapproved:architecture")

        def render(problems: Untrusted | None) -> RenderedPrompt:
            return role.render(threat_modeler.ThreatModelerInput(
                project=self.project, architecture=doc, components=components,
                is_llm_app=draft.is_llm_app, problems=problems))  # fmt: skip

        attempt = with_repair(
            self._gateway_for(),
            RoleName.THREAT_MODELER,
            ThreatModelDraft,
            render=render,
            check=lambda out: threat_modeler.problems(
                out, components=components, is_llm_app=draft.is_llm_app
            ),
            budget=self._budget,
            on_reply=lambda out: self._check(RoleName.THREAT_MODELER, out.injection_suspected),
        )
        if attempt.problems:
            raise DesignRejected(
                "the threat modeler's reply failed aipm's checks twice, so nothing was written",
                hint="Run `aipm design --regenerate` again, or try a stronger model.",
                data={"role": "threat_modeler", "problems": list(attempt.problems)},
            )
        inp = threat_modeler.ThreatModelerInput(
            project=self.project, architecture=doc, components=components,
            is_llm_app=draft.is_llm_app,
        )  # fmt: skip
        return role.postprocess(attempt.value, inp)

    def _generate(self) -> tuple[str, ...]:
        prd, prd_sha = self._prd_text()
        draft = self._architect(prd)
        arch_doc: ArchitectureDoc = architect.build_architecture(
            draft, project=self.project, prd_sha=prd_sha
        )
        arch_text, arch_sha = self.store.preview(arch_doc)
        threats = self._threat_model(draft, arch_text)
        tm_doc = threat_modeler.build_threat_model(
            threats, project=self.project, architecture_sha=arch_sha, is_llm_app=draft.is_llm_app
        )
        self.store.preview(tm_doc)  # every file is checked before the first one is written
        self.store.save_adrs(architect.build_adrs(draft))
        written_sha = self.store.save(arch_doc)
        if written_sha != arch_sha:  # pragma: no cover - preview and save render identically
            raise UsageError("architecture.md was not written as previewed")
        self.store.save(tm_doc)
        return ("architecture.md", "adr/", "threat-model.md")

    # ------------------------------------------------------------ G2

    def _g2(self, review: DesignReview) -> tuple[str, bool]:
        """Returns (approved | pending, whether the stack was copied); never touches trust."""
        if review.approved:
            return "approved", False
        if review.problems:
            self.notes.append("G2 cannot be approved yet: " + "; ".join(review.problems))
            return "pending", False
        if self.options.yes or (self.prompter is not None and self.prompter.approve_design(review)):
            return "approved", record_design(self.store, review)
        self.notes.append(
            "review .pm/architecture.md, .pm/threat-model.md and .pm/adr/, then run "
            "`aipm approve design`"
        )
        return "pending", False


__all__ = ["DesignOptions", "DesignPrompter", "DesignRejected", "DesignResult", "run"]
