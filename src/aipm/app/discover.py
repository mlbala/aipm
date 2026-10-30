"""`aipm discover`: the requirements interview, `requirements.yaml`, the PRD and G1 (§8, §7.2).

The loop lives here; the terminal lives in the CLI, behind the `Prompter` protocol. Without a
prompter the run is non-interactive: answers come from `--answers` and `--defaults`, and anything
still unanswered saves the state and exits 4 with the pending questions as JSON.

Every model reply passes the gateway's schema validation first. Its proposals then go through
deterministic code: coverage is scored and clamped by `aipm.domain.coverage`, question IDs are
allocated by aipm, and nothing a model writes can add a gate, change config, approve an artifact
or touch trust. `injection_suspected` stops a non-interactive run (exit 4) unless the user passed
`--accept-risk`, and asks an interactive user first; either way it is recorded as a security
event before anything from that reply is written.
"""

from collections.abc import Sequence
from dataclasses import dataclass, field
from enum import StrEnum
from pathlib import Path
from typing import Protocol

from aipm.app import runtime
from aipm.app.approve import is_approved, load_approvals, record_approval
from aipm.app.guards import InjectionSuspected, check_injection
from aipm.app.init import project_name
from aipm.app.inputs import AnswersFile, answer_text, load_answers, read_repo_file
from aipm.app.workspace import find_repo_root, require_initialized
from aipm.config.loader import load_config
from aipm.config.schema import Config
from aipm.domain.coverage import (
    StopReason,
    assumption_from_default,
    compute_coverage,
    proposals_from_scores,
    stop_reason,
)
from aipm.domain.errors import HumanInputRequired, UsageError
from aipm.domain.ids import is_valid_id, next_id
from aipm.domain.models import (
    Answer,
    AnswerSource,
    ApprovalGate,
    ArtifactKind,
    Assumption,
    Dimension,
    Mode,
    OpenQuestion,
    PrdDoc,
    ProjectInfo,
    RepoMapDoc,
    RequirementsDoc,
    RoleName,
    SecurityEventKind,
    Source,
    SourceKind,
)
from aipm.llm.cost import UsageLedger
from aipm.llm.gateway import Gateway, TokenBudget, open_gateway
from aipm.reporting.requirements_view import dimension_title, render_requirements_md
from aipm.roles import interviewer, prd_writer
from aipm.roles.interviewer import InterviewRound, ProposedQuestion, QuestionKind
from aipm.roles.prd_writer import PrdDraft, build_prd
from aipm.security.sanitize import decode_untrusted
from aipm.security.untrusted import Untrusted
from aipm.state.layout import artifact_name
from aipm.state.store import FileStateStore
from aipm.state.yamlio import dump_yaml

DESCRIBE_QUESTION = (
    "Describe the project in one paragraph: the problem, who it is for and what it must do."
)
REQUIREMENTS_MD = "requirements.md"
_BULK = "defaults for the rest of the round"
PRD_FILE = artifact_name(ArtifactKind.PRD)


class PendingQuestions(HumanInputRequired):
    """Questions are unanswered in a non-interactive run (exit 4); `data` lists them."""

    code = "PENDING_QUESTIONS"


# ---------------------------------------------------------------- what the prompter sees


@dataclass(frozen=True, slots=True)
class QuestionView:
    """A question to put to the user. All text is untrusted: print it with `print_untrusted`."""

    id: str
    dimension: str
    kind: str
    question: str
    options: tuple[str, ...] = ()
    default: tuple[str, ...] = ()
    why: str = ""
    blocking: bool = False

    def to_data(self) -> dict[str, object]:
        """The JSON form used for pending questions."""
        return {
            "id": self.id,
            "dimension": self.dimension,
            "kind": self.kind,
            "question": self.question,
            "options": list(self.options),
            "default": list(self.default),
            "why": self.why,
            "blocking": self.blocking,
        }


class ReplyKind(StrEnum):
    """What the user did with a question."""

    ANSWER = "answer"
    DEFAULT = "default"
    DEFAULTS_REST = "defaults_rest"
    DONE = "done"


@dataclass(frozen=True, slots=True)
class Reply:
    """The user's reply; `values` holds the chosen options or the typed text."""

    kind: ReplyKind
    values: tuple[str, ...] = ()


@dataclass(frozen=True, slots=True)
class ExtractedView:
    """An answer the interviewer found in the idea file."""

    id: str
    dimension: str
    question: str
    answer: str


class ExtractedAction(StrEnum):
    """What to do with one extracted answer."""

    CONFIRM = "confirm"
    EDIT = "edit"
    UNCONFIRMED = "unconfirmed"
    DROP = "drop"


@dataclass(frozen=True, slots=True)
class ExtractedDecision:
    """The user's decision on one extracted answer; `text` is the edited answer."""

    action: ExtractedAction
    text: str = ""


@dataclass(frozen=True, slots=True)
class AssumptionView:
    """An unconfirmed assumption from an earlier run."""

    id: str
    dimension: str
    statement: str


@dataclass(frozen=True, slots=True)
class CoverageView:
    """The coverage after a round."""

    score: float
    threshold: float
    rounds: int
    by_dimension: tuple[tuple[str, float], ...]


@dataclass(frozen=True, slots=True)
class PrdSummary:
    """What G1 shows (ARCHITECTURE §7.2): the PRD summary, assumptions and open questions."""

    path: str
    one_liner: str
    features: tuple[str, ...]
    non_functional: tuple[str, ...]
    assumptions: tuple[str, ...]
    open_questions: tuple[str, ...]


class Prompter(Protocol):
    """The interactive side of the interview, implemented by the CLI."""

    def describe(self) -> str:
        """Ask for a one-paragraph description."""
        ...

    def review_extracted(self, items: Sequence[ExtractedView]) -> list[ExtractedDecision]:
        """Show extracted answers for batch confirmation or editing; one decision per item."""
        ...

    def ask(self, question: QuestionView, *, number: int, total: int) -> Reply:
        """Ask one question."""
        ...

    def review_assumption(self, assumption: AssumptionView) -> Reply:
        """DEFAULT confirms it, ANSWER replaces it, DEFAULTS_REST leaves the rest, DONE stops."""
        ...

    def edit_answer(self, question: QuestionView, current: str) -> str:
        """Edit an existing answer."""
        ...

    def show_coverage(self, coverage: CoverageView) -> None:
        """Show the coverage after a round."""
        ...

    def confirm_risk(self, role: str, excerpts: Sequence[str]) -> bool:
        """Warn about suspected prompt injection; True continues."""
        ...

    def approve(self, summary: PrdSummary) -> bool:
        """G1: show the summary and ask for approval."""
        ...


# ---------------------------------------------------------------- options and result


@dataclass(frozen=True, slots=True)
class DiscoverOptions:
    """The command's flags."""

    from_file: Path | None = None
    answers: Path | None = None
    defaults: bool = False
    edit: str | None = None
    max_rounds: int | None = None
    threshold: float | None = None
    accept_risk: bool = False
    yes: bool = False


@dataclass(frozen=True, slots=True)
class DiscoverResult:
    """What `aipm discover` did, for the CLI to report."""

    repo_root: str
    score: float
    threshold: float
    rounds: int
    by_dimension: dict[str, float]
    stop: str | None
    answers: int
    assumptions: int
    open_questions: tuple[str, ...]
    blocking: tuple[str, ...]
    approval: str
    written: tuple[str, ...]
    usage: dict[str, object]
    warnings: tuple[str, ...]
    notes: tuple[str, ...]

    def to_data(self) -> dict[str, object]:
        """The `--json` payload."""
        return {
            "repo": self.repo_root,
            "coverage": {
                "score": self.score,
                "threshold": self.threshold,
                "rounds": self.rounds,
                "by_dimension": self.by_dimension,
            },
            "stop": self.stop,
            "answers": self.answers,
            "assumptions": self.assumptions,
            "open_questions": list(self.open_questions),
            "blocking": list(self.blocking),
            "approval": self.approval,
            "written": list(self.written),
            "usage": self.usage,
            "warnings": list(self.warnings),
            "notes": list(self.notes),
        }


def _check_limits(cfg: Config, opts: DiscoverOptions) -> tuple[float, int]:
    threshold = cfg.discover.coverage_threshold if opts.threshold is None else opts.threshold
    if not 0.0 <= threshold <= 1.0:
        raise UsageError("--threshold must be between 0 and 1")
    max_rounds = cfg.discover.max_rounds if opts.max_rounds is None else opts.max_rounds
    if not 1 <= max_rounds <= 20:
        raise UsageError("--max-rounds must be between 1 and 20")
    if opts.edit is not None and not is_valid_id("question", opts.edit):
        raise UsageError(f"--edit takes a question ID such as Q-004, not {opts.edit!r}")
    if opts.edit is not None and opts.from_file is not None:
        raise UsageError("--edit and --from cannot be combined")
    return threshold, max_rounds


def run(
    project: Path | None, *, options: DiscoverOptions, prompter: Prompter | None
) -> DiscoverResult:
    """Run the use case. `prompter` is None in a non-interactive run."""
    root = find_repo_root(project)
    require_initialized(root)
    cfg = load_config(root)
    threshold, max_rounds = _check_limits(cfg.config, options)
    redactor = runtime.user_redactor(root)
    store = runtime.open_repo_store(root, redactor=redactor)
    max_bytes = cfg.config.security.max_input_kib * 1024
    answers: tuple[AnswersFile, Source] | None = None
    if options.answers is not None:
        answers = load_answers(root, options.answers, max_bytes=max_bytes)
    ledger = UsageLedger()
    gateway = open_gateway(cfg.config.llm, redactor=redactor, ledger=ledger)
    with store.lock():
        session = _Discovery(
            root=root,
            cfg=cfg.config,
            store=store,
            gateway=gateway,
            ledger=ledger,
            prompter=prompter,
            options=options,
            answers=answers,
            threshold=threshold,
            max_rounds=max_rounds,
        )
        session.warnings.extend(cfg.warnings)
        return session.run()


# ---------------------------------------------------------------- the session


def _view(q: ProposedQuestion) -> QuestionView:
    return QuestionView(
        id=q.id,
        dimension=q.dimension.value,
        kind=q.kind.value,
        question=q.question,
        options=tuple(q.options),
        default=tuple(q.default),
        why=q.why,
        blocking=q.blocking,
    )


def _open_view(q: OpenQuestion) -> QuestionView:
    return QuestionView(
        id=q.id,
        dimension=q.dimension.value,
        kind=QuestionKind.TEXT.value,
        question=q.question,
        why="Still open from an earlier run.",
        blocking=q.blocking,
    )


@dataclass
class _Discovery:
    root: Path
    cfg: Config
    store: FileStateStore
    gateway: Gateway
    ledger: UsageLedger
    prompter: Prompter | None
    options: DiscoverOptions
    answers: tuple[AnswersFile, Source] | None
    threshold: float
    max_rounds: int
    warnings: list[str] = field(default_factory=list[str])
    notes: list[str] = field(default_factory=list[str])
    used_ids: set[str] = field(default_factory=set[str])
    used_keys: set[str] = field(default_factory=set[str])
    rounds_run: int = 0
    user_done: bool = False
    stop: StopReason | None = None
    repo_map: Untrusted | None = None
    _extracted_ids: list[str] = field(default_factory=list[str])

    # ------------------------------------------------------------ top level

    def run(self) -> DiscoverResult:
        doc = self._load()
        self.used_ids = {a.id for a in doc.answers} | {q.id for q in doc.open_questions}
        if self.options.edit is not None:
            self._edit(doc)
        else:
            self._interview(doc)
        self._save(doc)
        self._write_prd(doc)
        approval = self._g1(doc)
        self._report_unused_answers()
        written = (artifact_name(ArtifactKind.REQUIREMENTS), REQUIREMENTS_MD, PRD_FILE)
        if approval == "approved":
            written += (artifact_name(ArtifactKind.APPROVALS),)
        return DiscoverResult(
            repo_root=str(self.root),
            score=doc.coverage.score,
            threshold=self.threshold,
            rounds=doc.coverage.rounds,
            by_dimension={d.value: s for d, s in doc.coverage.by_dimension.items()},
            stop=None if self.stop is None else self.stop.value,
            answers=len(doc.answers),
            assumptions=len(doc.assumptions),
            open_questions=tuple(q.id for q in doc.open_questions),
            blocking=tuple(q.id for q in doc.open_questions if q.blocking),
            approval=approval,
            written=written,
            usage=self.ledger.to_data(),
            warnings=tuple(self.warnings),
            notes=tuple(self.notes),
        )

    def _load(self) -> RequirementsDoc:
        mode = Mode.GREENFIELD
        if self.store.exists(ArtifactKind.REPO_MAP):
            repo_map = self.store.load(ArtifactKind.REPO_MAP)
            if isinstance(repo_map, RepoMapDoc):
                mode = repo_map.meta.mode
                if mode is Mode.BROWNFIELD:
                    self.repo_map = Untrusted(repo_map.body, source="repo-map.md")
        if self.store.exists(ArtifactKind.REQUIREMENTS):
            doc = self.store.load(ArtifactKind.REQUIREMENTS)
            if not isinstance(doc, RequirementsDoc):  # pragma: no cover - the store's mapping
                raise UsageError("requirements.yaml did not load as requirements")
            return doc
        name = self.cfg.project.name or project_name(self.root) or "project"
        return RequirementsDoc(project=ProjectInfo(name=name), mode=mode)

    def _save(self, doc: RequirementsDoc) -> None:
        self.store.save(doc)
        self.store.write_text(REQUIREMENTS_MD, render_requirements_md(doc))

    def _budget(self) -> TokenBudget:
        return TokenBudget(self.cfg.budget.run_tokens - self.ledger.total_tokens)

    def _new_id(self) -> str:
        qid = next_id("question", self.used_ids)
        self.used_ids.add(qid)
        return qid

    def _add_source(self, doc: RequirementsDoc, source: Source) -> None:
        if source not in doc.sources:
            doc.sources.append(source)

    # ------------------------------------------------------------ answers from the file

    def _lookup(self, qid: str, dimension: Dimension | None) -> str | None:
        """An answer by question ID, else by dimension. A yes or no answers only by ID."""
        if self.answers is None:
            return None
        values = self.answers[0].answers
        if qid in values:
            self.used_keys.add(qid)
            return answer_text(values[qid]) or None
        if dimension is not None and dimension.value in values:
            value = values[dimension.value]
            if isinstance(value, bool):
                return None
            self.used_keys.add(dimension.value)
            return answer_text(value) or None
        return None

    def _report_unused_answers(self) -> None:
        if self.answers is None:
            return
        unused = sorted(set(self.answers[0].answers) - self.used_keys)
        if unused:
            self.notes.append(f"answers not used in this run: {', '.join(unused)}")

    def _answered_from_file(self, doc: RequirementsDoc) -> None:
        if self.answers is not None:
            self._add_source(doc, self.answers[1])

    # ------------------------------------------------------------ the interview

    def _interview(self, doc: RequirementsDoc) -> None:
        fresh = not (doc.answers or doc.assumptions or doc.open_questions)
        from_file = self.options.from_file
        idea = self._read_idea(doc, from_file) if from_file is not None else None
        if fresh and idea is None:
            self._describe(doc)
        if not fresh:
            self._revisit(doc)
        extract = idea is not None
        while True:
            out = self._ask_interviewer(doc, extract=extract, idea=idea)
            if out.one_liner.strip() and not doc.project.one_liner:
                doc.project = doc.project.model_copy(update={"one_liner": out.one_liner.strip()})
            if extract:
                self._take_extracted(doc, out)
                extract = False
            proposals = out.coverage.as_map()
            doc.coverage = compute_coverage(doc, proposals, rounds=doc.coverage.rounds)
            self._save(doc)
            self.stop = stop_reason(
                score=doc.coverage.score,
                threshold=self.threshold,
                rounds=self.rounds_run,
                max_rounds=self.max_rounds,
                has_questions=bool(out.questions),
                user_done=self.user_done,
            )
            if self.stop is not None:
                self._park(doc, out.questions, everything=self.stop is StopReason.MAX_ROUNDS)
                return
            self._round(doc, out.questions)
            self.rounds_run += 1
            doc.coverage = compute_coverage(doc, proposals, rounds=doc.coverage.rounds + 1)
            self._save(doc)
            if self.prompter is not None:
                self.prompter.show_coverage(self._coverage_view(doc))

    def _coverage_view(self, doc: RequirementsDoc) -> CoverageView:
        return CoverageView(
            score=doc.coverage.score,
            threshold=self.threshold,
            rounds=doc.coverage.rounds,
            by_dimension=tuple((d.value, doc.coverage.by_dimension.get(d, 0.0)) for d in Dimension),
        )

    def _read_idea(self, doc: RequirementsDoc, from_file: Path) -> Untrusted:
        max_bytes = self.cfg.security.max_input_kib * 1024
        file = read_repo_file(self.root, from_file, max_bytes=max_bytes, what="--from")
        clean = decode_untrusted(file.data, source=file.relpath, max_bytes=max_bytes)
        if clean.invisible_removed:
            self.store.append_event(
                SecurityEventKind.INJECTION_SIGNAL,
                source=file.relpath,
                detail=f"{clean.invisible_removed} invisible characters removed",
            )
            self.warnings.append(
                f"{file.relpath}: removed {clean.invisible_removed} invisible characters "
                "(possible hidden instructions); see `aipm status`"
            )
        self._add_source(doc, Source(kind=SourceKind.FILE, path=file.relpath, sha256=file.sha256))
        return Untrusted(clean.text, source=f"file:{file.relpath}")

    def _describe(self, doc: RequirementsDoc) -> None:
        if self.prompter is not None:
            text = self.prompter.describe().strip()
            self._add_source(doc, Source(kind=SourceKind.TERMINAL))
        elif self.answers is not None and self.answers[0].description.strip():
            text = self.answers[0].description.strip()
            self._answered_from_file(doc)
        else:
            view = QuestionView(id="description", dimension="problem_goals", kind="text",
                                question=DESCRIBE_QUESTION)  # fmt: skip
            raise PendingQuestions(
                "a project description is needed",
                hint="Pass --from FILE, or set `description:` in the --answers file.",
                data={"pending": [view.to_data()]},
            )
        if not text:
            raise UsageError("the description is empty")
        doc.answers.append(
            Answer(
                id=self._new_id(),
                dimension=Dimension.PROBLEM_GOALS,
                question=DESCRIBE_QUESTION,
                answer=text[:4000],
                source=AnswerSource.USER,
                confirmed=True,
            )
        )

    def _requirements_text(self, doc: RequirementsDoc) -> str:
        keep = {"project", "answers", "assumptions", "open_questions"}
        data = doc.model_dump(mode="json", include=keep)
        return dump_yaml(data)

    def _ask_interviewer(
        self, doc: RequirementsDoc, *, extract: bool, idea: Untrusted | None
    ) -> InterviewRound:
        role = interviewer.create()
        inp = interviewer.InterviewerInput(
            project=doc.project.name,
            round=doc.coverage.rounds + 1,
            extract=extract,
            questions_per_round=self.cfg.discover.questions_per_round,
            scores=dict(doc.coverage.by_dimension),
            requirements=Untrusted(self._requirements_text(doc), source="draft:requirements"),
            used_ids=frozenset(self.used_ids),
            idea=idea,
            repo_map=self.repo_map,
        )
        result = self.gateway.run(
            RoleName.INTERVIEWER, role.render(inp), InterviewRound, budget=self._budget()
        )
        out = role.postprocess(result.value, inp)
        self._check_injection(RoleName.INTERVIEWER, out.injection_suspected)
        self._extracted_ids = interviewer.extraction_ids(out, inp.used_ids)
        self.used_ids.update(self._extracted_ids)
        self.used_ids.update(q.id for q in out.questions)
        return out

    def _take_extracted(self, doc: RequirementsDoc, out: InterviewRound) -> None:
        known = {(a.dimension, a.question, a.answer) for a in doc.answers}
        pairs = [
            (qid, e)
            for qid, e in zip(self._extracted_ids, out.extracted, strict=True)
            if (e.dimension, e.question, e.answer) not in known
        ]
        fresh = [e for _, e in pairs]
        items = [
            ExtractedView(id=qid, dimension=e.dimension.value, question=e.question, answer=e.answer)
            for qid, e in pairs
        ]
        if not items:
            return
        if self.prompter is not None:
            decisions = self.prompter.review_extracted(items)
            if len(decisions) != len(items):
                raise UsageError("every extracted answer needs a decision")
        elif self.answers is not None and self.answers[0].confirm_extracted:
            decisions = [ExtractedDecision(ExtractedAction.CONFIRM)] * len(items)
            self._answered_from_file(doc)
        else:
            decisions = [ExtractedDecision(ExtractedAction.UNCONFIRMED)] * len(items)
            self.notes.append(
                f"{len(items)} answers extracted from the idea file are unconfirmed and do not "
                "count; set `confirm_extracted: true` in the answers file, or run interactively"
            )
        for item, extracted, decision in zip(items, fresh, decisions, strict=True):
            if decision.action is ExtractedAction.DROP:
                continue
            edited = decision.action is ExtractedAction.EDIT and decision.text.strip()
            doc.answers.append(
                Answer(
                    id=item.id,
                    dimension=extracted.dimension,
                    question=item.question,
                    answer=decision.text.strip()[:4000] if edited else item.answer,
                    source=AnswerSource.USER if edited else AnswerSource.FILE,
                    confirmed=decision.action is not ExtractedAction.UNCONFIRMED,
                )
            )

    # ------------------------------------------------------------ one round of questions

    def _answer(self, doc: RequirementsDoc, q: ProposedQuestion | OpenQuestion, text: str) -> None:
        doc.answers.append(
            Answer(
                id=q.id,
                dimension=q.dimension,
                question=q.question,
                answer=text[:4000],
                source=AnswerSource.USER,
                confirmed=True,
            )
        )

    def _assume(
        self, doc: RequirementsDoc, q: ProposedQuestion, *, confirmed: bool, reason: str
    ) -> None:
        aid = next_id("assumption", [a.id for a in doc.assumptions])
        doc.assumptions.append(
            assumption_from_default(
                assumption_id=aid,
                dimension=q.dimension,
                question=q.question,
                default="; ".join(q.default),
                reason=reason,
                confirmed=confirmed,
            )
        )

    def _open(self, doc: RequirementsDoc, q: ProposedQuestion | OpenQuestion) -> None:
        if any(o.id == q.id for o in doc.open_questions) or len(doc.open_questions) >= 100:
            return
        doc.open_questions.append(
            OpenQuestion(id=q.id, dimension=q.dimension, question=q.question, blocking=q.blocking)
        )

    def _park(
        self, doc: RequirementsDoc, questions: Sequence[ProposedQuestion], *, everything: bool
    ) -> None:
        """Keep the unasked questions of the final call as open questions."""
        for q in questions:
            if everything or q.blocking:
                self._open(doc, q)

    def _default_or_open(
        self, doc: RequirementsDoc, q: ProposedQuestion, *, confirmed: bool, reason: str
    ) -> None:
        if q.default:
            self._assume(doc, q, confirmed=confirmed, reason=reason)
        else:
            self._open(doc, q)

    def _round(self, doc: RequirementsDoc, questions: Sequence[ProposedQuestion]) -> None:
        if self.prompter is None:
            self._round_from_file(doc, questions)
            return
        bulk = False
        for number, q in enumerate(questions, start=1):
            if self.user_done:
                self._open(doc, q)
            elif bulk:
                self._default_or_open(doc, q, confirmed=False, reason=_BULK)
            else:
                reply = self.prompter.ask(_view(q), number=number, total=len(questions))
                bulk = self._apply_reply(doc, q, reply)

    def _apply_reply(self, doc: RequirementsDoc, q: ProposedQuestion, reply: Reply) -> bool:
        """Record one reply; True when the rest of the round takes the defaults."""
        kind = reply.kind
        if kind is ReplyKind.ANSWER and frozenset(reply.values) == frozenset(q.default):
            kind = ReplyKind.DEFAULT
        if kind is ReplyKind.ANSWER:
            text = "; ".join(v.strip() for v in reply.values if v.strip())
            if text:
                self._answer(doc, q, text)
            else:
                self._open(doc, q)
        elif kind is ReplyKind.DEFAULT:
            self._default_or_open(doc, q, confirmed=True, reason="default accepted")
        elif kind is ReplyKind.DEFAULTS_REST:
            self._default_or_open(doc, q, confirmed=False, reason=_BULK)
            return True
        else:
            self.user_done = True
            self._open(doc, q)
        return False

    def _round_from_file(self, doc: RequirementsDoc, questions: Sequence[ProposedQuestion]) -> None:
        pending: list[ProposedQuestion] = []
        for q in questions:
            # A confirm question is answered by its ID only: a dimension-wide answer must never
            # say "yes" to a question the model wrote (security review, step 03).
            by_dimension = None if q.kind is QuestionKind.CONFIRM else q.dimension
            text = self._lookup(q.id, by_dimension)
            if text is not None:
                self._answer(doc, q, text)
                self._answered_from_file(doc)
            elif self.options.defaults and q.default:
                self._assume(doc, q, confirmed=False, reason="--defaults")
            else:
                pending.append(q)
        if pending:
            for q in pending:
                self._open(doc, q)
            self._raise_pending(doc, [_view(q) for q in pending])

    def _raise_pending(self, doc: RequirementsDoc, views: Sequence[QuestionView]) -> None:
        doc.coverage = compute_coverage(
            doc, proposals_from_scores(doc.coverage.by_dimension), rounds=doc.coverage.rounds
        )
        self._save(doc)
        ids = ", ".join(v.id for v in views)
        raise PendingQuestions(
            f"{len(views)} questions need answers: {ids}",
            hint="Answer them by ID or dimension in --answers FILE, pass --defaults, or run "
            "interactively. The progress so far is saved.",
            data={"pending": [v.to_data() for v in views]},
        )

    # ------------------------------------------------------------ re-runs

    def _revisit(self, doc: RequirementsDoc) -> None:
        """A re-run starts with the open questions and the unconfirmed assumptions (§8.2)."""
        if self.prompter is None:
            self._revisit_from_file(doc)
            return
        for q in list(doc.open_questions):
            if self.user_done:
                return
            reply = self.prompter.ask(_open_view(q), number=1, total=1)
            if reply.kind is ReplyKind.DONE:
                self.user_done = True
                return
            if reply.kind is ReplyKind.DEFAULTS_REST:
                break
            text = "; ".join(v.strip() for v in reply.values if v.strip())
            if reply.kind is ReplyKind.ANSWER and text:
                doc.open_questions.remove(q)
                self._answer(doc, q, text)
        for a in [a for a in doc.assumptions if not a.confirmed]:
            reply = self.prompter.review_assumption(
                AssumptionView(id=a.id, dimension=a.dimension.value, statement=a.statement)
            )
            if reply.kind is ReplyKind.DONE:
                self.user_done = True
                return
            if reply.kind is ReplyKind.DEFAULTS_REST:
                return
            self._settle_assumption(doc, a, reply)

    def _settle_assumption(self, doc: RequirementsDoc, a: Assumption, reply: Reply) -> None:
        text = "; ".join(v.strip() for v in reply.values if v.strip())
        index = doc.assumptions.index(a)
        if reply.kind is ReplyKind.DEFAULT:
            doc.assumptions[index] = a.model_copy(update={"confirmed": True})
        elif reply.kind is ReplyKind.ANSWER and text:
            del doc.assumptions[index]
            doc.answers.append(
                Answer(
                    id=self._new_id(),
                    dimension=a.dimension,
                    question=f"Replaces assumption {a.id}: {a.statement}"[:500],
                    answer=text[:4000],
                    source=AnswerSource.USER,
                    confirmed=True,
                )
            )

    def _revisit_from_file(self, doc: RequirementsDoc) -> None:
        pending: list[QuestionView] = []
        for q in list(doc.open_questions):
            text = self._lookup(q.id, q.dimension)
            if text is None:
                pending.append(_open_view(q))
                continue
            doc.open_questions.remove(q)
            self._answer(doc, q, text)
            self._answered_from_file(doc)
        values = self.answers[0].answers if self.answers is not None else {}
        for a in [a for a in doc.assumptions if not a.confirmed and a.id in values]:
            self.used_keys.add(a.id)
            value = values[a.id]
            if value is False:
                continue
            reply = (
                Reply(ReplyKind.DEFAULT)
                if value is True
                else Reply(ReplyKind.ANSWER, (answer_text(value),))
            )
            self._settle_assumption(doc, a, reply)
            self._answered_from_file(doc)
        if pending:
            self._raise_pending(doc, pending)

    def _edit(self, doc: RequirementsDoc) -> None:
        qid = self.options.edit
        answer = next((a for a in doc.answers if a.id == qid), None)
        if qid is None or answer is None:
            raise UsageError(
                f"{qid} is not an answered question",
                hint="See .pm/requirements.md for the answer IDs.",
            )
        view = QuestionView(id=answer.id, dimension=answer.dimension.value, kind="text",
                            question=answer.question, default=(answer.answer,))  # fmt: skip
        if self.prompter is not None:
            text = self.prompter.edit_answer(view, answer.answer).strip()
        else:
            found = self._lookup(qid, None)
            if found is None:
                raise PendingQuestions(
                    f"--edit {qid} needs the new answer",
                    hint=f"Set {qid} in --answers FILE, or run interactively.",
                    data={"pending": [view.to_data()]},
                )
            text = found
            self._answered_from_file(doc)
        if not text:
            raise UsageError("the new answer is empty")
        index = doc.answers.index(answer)
        doc.answers[index] = answer.model_copy(
            update={"answer": text[:4000], "source": AnswerSource.USER, "confirmed": True}
        )
        doc.coverage = compute_coverage(
            doc, proposals_from_scores(doc.coverage.by_dimension), rounds=doc.coverage.rounds
        )
        self.notes.append(f"{qid} changed; the PRD was regenerated and needs approval again")

    # ------------------------------------------------------------ injection, PRD and G1

    def _check_injection(self, role: RoleName, excerpts: Sequence[str]) -> None:
        confirm = self.prompter.confirm_risk if self.prompter is not None else None
        check_injection(self.store, role, excerpts, confirm=confirm,
                        accept_risk=self.options.accept_risk, warnings=self.warnings)  # fmt: skip

    def _write_prd(self, doc: RequirementsDoc) -> None:
        text = self.store.read_text(ArtifactKind.REQUIREMENTS)
        sha = self.store.sha256(ArtifactKind.REQUIREMENTS)
        if text is None or sha is None:  # pragma: no cover - saved just before
            raise UsageError("requirements.yaml is missing")
        role = prd_writer.create()
        inp = prd_writer.PrdWriterInput(
            project=doc.project.name, requirements=Untrusted(text, source="draft:requirements")
        )
        result = self.gateway.run(
            RoleName.PRD_WRITER, role.render(inp), PrdDraft, budget=self._budget()
        )
        draft = role.postprocess(result.value, inp)
        self._check_injection(RoleName.PRD_WRITER, draft.injection_suspected)
        self.store.save(build_prd(draft, doc, requirements_sha=sha))

    def _summary(self, doc: RequirementsDoc) -> PrdSummary:
        prd = self.store.load(ArtifactKind.PRD)
        if not isinstance(prd, PrdDoc):  # pragma: no cover - the store's mapping
            raise UsageError("prd.md did not load as a PRD")
        features = tuple(f"{f.id} ({f.priority.value}): {f.title}" for f in prd.meta.features)
        nfrs = tuple(f"{n.id} ({n.category}): {n.statement}" for n in prd.meta.non_functional)
        return PrdSummary(
            path=f".pm/{PRD_FILE}",
            one_liner=doc.project.one_liner,
            features=features,
            non_functional=nfrs,
            assumptions=tuple(
                f"{a.id} ({dimension_title(a.dimension)}): {a.statement}" for a in doc.assumptions
            ),
            open_questions=tuple(
                f"{q.id}{' (blocking)' if q.blocking else ''}: {q.question}"
                for q in doc.open_questions
            ),
        )

    def _g1(self, doc: RequirementsDoc) -> str:
        """G1 (ARCHITECTURE §7.2). Returns approved, pending or blocked; never touches trust."""
        blocking = [q.id for q in doc.open_questions if q.blocking]
        if blocking:
            self.notes.append(
                f"G1 is blocked until these are answered or assumed: {', '.join(blocking)}"
            )
            return "blocked"
        sha = self.store.sha256(ArtifactKind.PRD)
        if sha is None:  # pragma: no cover - written just before
            raise UsageError("prd.md is missing")
        if is_approved(load_approvals(self.store), ApprovalGate.G1, PRD_FILE, sha):
            return "approved"
        if self.options.yes:
            record_approval(self.store, ApprovalGate.G1, PRD_FILE, sha)
            return "approved"
        if self.prompter is not None and self.prompter.approve(self._summary(doc)):
            record_approval(self.store, ApprovalGate.G1, PRD_FILE, sha)
            return "approved"
        self.notes.append("review .pm/prd.md, then run `aipm approve prd`")
        return "pending"


__all__ = [
    "AssumptionView",
    "CoverageView",
    "DiscoverOptions",
    "DiscoverResult",
    "ExtractedAction",
    "ExtractedDecision",
    "ExtractedView",
    "InjectionSuspected",
    "PendingQuestions",
    "PrdSummary",
    "Prompter",
    "QuestionView",
    "Reply",
    "ReplyKind",
    "run",
]
