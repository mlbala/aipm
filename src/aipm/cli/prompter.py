"""The interactive side of `aipm discover`, with questionary (ARCHITECTURE §8.2).

Question text, options, extracted answers and injection excerpts come from a model or a file, so
they are printed with `print_untrusted` (sanitized, no markup, no escapes) and every option label
is sanitized before questionary renders it (SECURITY.md §7.10). questionary only ever shows
aipm's own short prompt messages. Enter accepts the default; each question also offers "use
defaults for the rest of this round" and "I'm done". questionary is imported lazily, so
`aipm --help` stays fast.
"""

from collections.abc import Sequence
from typing import Any

from aipm.app.discover import (
    AssumptionView,
    CoverageView,
    ExtractedAction,
    ExtractedDecision,
    ExtractedView,
    PrdSummary,
    QuestionView,
    Reply,
    ReplyKind,
)
from aipm.cli.output import print_untrusted
from aipm.security.sanitize import sanitize_text

REST = "(use defaults for the rest of this round)"
DONE = "(I'm done)"
_REST_KEY = "__rest__"
_DONE_KEY = "__done__"
_TEXT_HELP = "Answer (Enter keeps the default, /d = defaults for the rest of the round, /q = done):"


def label(text: str, limit: int = 160) -> str:
    """One sanitized line for a questionary choice or default."""
    clean = " ".join(sanitize_text(text, source="choice").text.split())
    return clean if len(clean) <= limit else clean[: limit - 1] + "…"


class QuestionaryPrompter:
    """`aipm.app.discover.Prompter` over questionary. `input`/`output` are for tests."""

    def __init__(self, *, input: Any = None, output: Any = None) -> None:
        self._io: dict[str, Any] = {}
        if input is not None:
            self._io["input"] = input
        if output is not None:
            self._io["output"] = output

    # ------------------------------------------------------------ questionary wrappers

    def _select(self, message: str, choices: Sequence[tuple[str, str]], default: str | None) -> str:
        import questionary

        options = [questionary.Choice(title=title, value=value) for title, value in choices]
        found = next((c for c in options if c.value == default), None)
        answer = questionary.select(message, choices=options, default=found, **self._io)
        return str(answer.unsafe_ask())

    def _text(self, message: str, default: str = "") -> str:
        import questionary

        return str(questionary.text(message, default=default, **self._io).unsafe_ask())

    def _yes_no(self, message: str) -> bool:
        return self._select(message, [("No", "no"), ("Yes", "yes")], "no") == "yes"

    # ------------------------------------------------------------ the Prompter protocol

    def describe(self) -> str:
        """Ask for a one-paragraph description."""
        print_untrusted(
            "Describe the project in one paragraph: the problem, who it is for and what it must do."
        )
        return self._text("Description:")

    def review_extracted(self, items: Sequence[ExtractedView]) -> list[ExtractedDecision]:
        """Show every extracted answer, then confirm all, none, or one by one."""
        print_untrusted(f"Found {len(items)} answers in the idea file:")
        for item in items:
            print_untrusted(f"  {item.id} ({item.dimension}) {item.question}")
            print_untrusted(f"      {item.answer}")
        choice = self._select(
            "Use these answers?",
            [
                ("Confirm all", "all"),
                ("Review them one by one", "each"),
                ("Leave them unconfirmed (they will not count)", "none"),
            ],
            "all",
        )
        if choice == "all":
            return [ExtractedDecision(ExtractedAction.CONFIRM)] * len(items)
        if choice == "none":
            return [ExtractedDecision(ExtractedAction.UNCONFIRMED)] * len(items)
        return [self._review_one(item) for item in items]

    def _review_one(self, item: ExtractedView) -> ExtractedDecision:
        print_untrusted(f"{item.id} ({item.dimension}) {item.question}")
        print_untrusted(f"    {item.answer}")
        action = self._select(
            "This answer:",
            [
                ("Confirm", "confirm"),
                ("Edit", "edit"),
                ("Leave unconfirmed", "unconfirmed"),
                ("Drop it", "drop"),
            ],
            "confirm",
        )
        if action == "edit":
            text = self._text("Answer:", label(item.answer, limit=4000))
            return ExtractedDecision(ExtractedAction.EDIT, text)
        return ExtractedDecision(ExtractedAction(action))

    def ask(self, question: QuestionView, *, number: int, total: int) -> Reply:
        """Ask one question in the form its kind calls for."""
        flag = " [blocking]" if question.blocking else ""
        print_untrusted(f"\n[{number}/{total}] {question.id} ({question.dimension}){flag}")
        print_untrusted(question.question)
        if question.why:
            print_untrusted(f"  why: {question.why}")
        if question.kind == "multi":
            return self._ask_multi(question)
        if question.kind in ("single", "confirm"):
            return self._ask_choice(question)
        if question.default:
            print_untrusted(f"  default: {question.default[0]}")
        answer = self._text(_TEXT_HELP).strip()
        if answer == "/d":
            return Reply(ReplyKind.DEFAULTS_REST)
        if answer == "/q":
            return Reply(ReplyKind.DONE)
        if not answer:
            return Reply(ReplyKind.DEFAULT)
        return Reply(ReplyKind.ANSWER, (answer,))

    def _ask_choice(self, question: QuestionView) -> Reply:
        options = question.options if question.kind == "single" else ("yes", "no")
        choices = [(label(option), str(i)) for i, option in enumerate(options)]
        choices += [(REST, _REST_KEY), (DONE, _DONE_KEY)]
        default = None
        if question.default and question.default[0] in options:
            default = str(options.index(question.default[0]))
        picked = self._select("Answer:", choices, default)
        if picked == _REST_KEY:
            return Reply(ReplyKind.DEFAULTS_REST)
        if picked == _DONE_KEY:
            return Reply(ReplyKind.DONE)
        return Reply(ReplyKind.ANSWER, (options[int(picked)],))

    def _ask_multi(self, question: QuestionView) -> Reply:
        import questionary

        choices = [
            questionary.Choice(title=label(o), value=str(i), checked=o in question.default)
            for i, o in enumerate(question.options)
        ]
        choices += [
            questionary.Choice(title=REST, value=_REST_KEY),
            questionary.Choice(title=DONE, value=_DONE_KEY),
        ]
        picked = [
            str(v)
            for v in questionary.checkbox(
                "Answer (space selects, Enter confirms):", choices=choices, **self._io
            ).unsafe_ask()
        ]
        if _DONE_KEY in picked:
            return Reply(ReplyKind.DONE)
        if _REST_KEY in picked:
            return Reply(ReplyKind.DEFAULTS_REST)
        return Reply(ReplyKind.ANSWER, tuple(question.options[int(v)] for v in picked))

    def review_assumption(self, assumption: AssumptionView) -> Reply:
        """Confirm, change or keep an unconfirmed assumption."""
        print_untrusted(f"\n{assumption.id} ({assumption.dimension}) assumed:")
        print_untrusted(f"  {assumption.statement}")
        action = self._select(
            "This assumption:",
            [
                ("Confirm it", "confirm"),
                ("Change it", "change"),
                ("Leave it unconfirmed", "leave"),
                (REST, _REST_KEY),
                (DONE, _DONE_KEY),
            ],
            "confirm",
        )
        if action == "confirm":
            return Reply(ReplyKind.DEFAULT)
        if action == "change":
            return Reply(ReplyKind.ANSWER, (self._text("Your answer:"),))
        if action == _REST_KEY:
            return Reply(ReplyKind.DEFAULTS_REST)
        if action == _DONE_KEY:
            return Reply(ReplyKind.DONE)
        return Reply(ReplyKind.ANSWER, ())

    def edit_answer(self, question: QuestionView, current: str) -> str:
        """Edit an existing answer."""
        print_untrusted(f"{question.id} ({question.dimension}) {question.question}")
        return self._text("New answer:", label(current, limit=4000))

    def show_coverage(self, coverage: CoverageView) -> None:
        """Print the coverage after a round."""
        print_untrusted(
            f"\nCoverage {coverage.score:.2f} (target {coverage.threshold:.2f}) after "
            f"{coverage.rounds} rounds"
        )
        low = [f"{name} {score:.2f}" for name, score in coverage.by_dimension if score < 1.0]
        if low:
            print_untrusted("  still open: " + ", ".join(low))

    def confirm_risk(self, role: str, excerpts: Sequence[str]) -> bool:
        """Warn about suspected prompt injection and ask whether to continue."""
        print_untrusted(
            f"\nwarning: the {role} found what look like instructions hidden in the input:",
            err=True,
        )
        for excerpt in excerpts:
            print_untrusted(f"  > {excerpt}", err=True)
        print_untrusted(
            "aipm ignores them, but review the input before you rely on the result.", err=True
        )
        return self._yes_no("Continue anyway?")

    def approve(self, summary: PrdSummary) -> bool:
        """G1: show the PRD summary, assumptions and open questions, then ask."""
        print_untrusted(f"\nPRD written to {summary.path}")
        if summary.one_liner:
            print_untrusted(summary.one_liner)
        for title, lines in (
            ("Features", summary.features),
            ("Non-functional requirements", summary.non_functional),
            ("Assumptions", summary.assumptions),
            ("Open questions", summary.open_questions),
        ):
            print_untrusted(f"{title}:")
            for line in lines or ("(none)",):
                print_untrusted(f"  - {line}")
        return self._yes_no("Approve the PRD (G1)?")


def make_prompter() -> QuestionaryPrompter:
    """The prompter for a real terminal (tests replace this)."""
    return QuestionaryPrompter()
