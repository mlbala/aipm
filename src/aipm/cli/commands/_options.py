"""Option and argument types shared by several commands (ARCHITECTURE §16)."""

from typing import Annotated

import typer

TaskId = Annotated[str, typer.Argument(metavar="T-ID", help="Task ID, for example T-007.")]

AcceptRisk = Annotated[
    bool,
    typer.Option(
        "--accept-risk",
        help="Continue in non-interactive mode when a role reports suspected prompt injection.",
    ),
]
AcceptStale = Annotated[
    bool,
    typer.Option(
        "--accept-stale",
        help="Run on stale upstream artifacts. The override is recorded in approvals.yaml.",
    ),
]
Tool = Annotated[
    str | None,
    typer.Option("--tool", help="Coding tool: claude, codex, copilot or gemini."),
]
Budget = Annotated[
    float | None,
    typer.Option("--budget", metavar="USD", help="Spend limit for the run, in USD."),
]
Timeout = Annotated[
    str | None,
    typer.Option("--timeout", metavar="DURATION", help="Timeout per task, for example 20m."),
]
Parallel = Annotated[
    int | None,
    typer.Option("--parallel", metavar="N", help="Tasks to run at once (at most 8)."),
]
MaxRetries = Annotated[
    int | None,
    typer.Option("--max-retries", metavar="N", help="Fix attempts per task."),
]
Only = Annotated[
    str | None,
    typer.Option("--only", metavar="T-IDs", help="Comma-separated task IDs to build."),
]
DryRun = Annotated[
    bool,
    typer.Option("--dry-run", help="Compile prompts and print the schedule and argv only."),
]
