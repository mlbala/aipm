"""`aipm setup` (ADR-0033): write the user config and optionally store the key in the keychain.

Interactive only: without a terminal it exits 2. `--yes` never skips its confirmation. Every
question and answer here is aipm's own short text or what the user types; file content is
printed with `print_untrusted`.
"""

from collections.abc import Sequence
from typing import Any

import typer

from aipm.cli.output import global_options, handled, is_interactive, print_untrusted, succeed
from aipm.domain.errors import UsageError


class _QuestionaryPrompter:
    """`aipm.app.setup.SetupPrompter` over questionary (imported lazily, as in `discover`)."""

    def __init__(self) -> None:
        import questionary

        self._q: Any = questionary

    def _ask(self, question: Any) -> Any:
        answer = question.unsafe_ask()
        if answer is None:
            raise UsageError("setup cancelled")
        return answer

    def choose(self, message: str, choices: Sequence[tuple[str, str]], default: str) -> str:
        options = [self._q.Choice(title=title, value=value) for title, value in choices]
        found = next((o for o in options if o.value == default), options[0])
        return str(self._ask(self._q.select(message, choices=options, default=found)))

    def text(self, message: str, default: str) -> str:
        return str(self._ask(self._q.text(message, default=default)))

    def secret(self, message: str) -> str:
        return str(self._ask(self._q.password(message)))

    def confirm(self, message: str, default: bool) -> bool:
        return bool(self._ask(self._q.confirm(message, default=default)))

    def show(self, line: str) -> None:
        print_untrusted(line, source="setup")


def command(ctx: typer.Context) -> None:
    """Choose the model provider and models, and store your API key in the keychain."""
    opts = global_options(ctx)
    with handled(ctx, "setup"):
        if not is_interactive(ctx):
            raise UsageError(
                "aipm setup needs a terminal",
                hint="Write the user config yourself: see the README, 'Set up your model "
                "provider and API keys'.",
            )
        from aipm.app import setup as use_case

        if opts.yes:
            print_untrusted("note: --yes does not skip setup's questions or its confirmation")
        result = use_case.run(_QuestionaryPrompter())
        succeed(ctx, "setup", result.data)
