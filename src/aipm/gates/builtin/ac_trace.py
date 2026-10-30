"""ac_trace: every AC ID of the task appears in a test file that ran (ARCHITECTURE §13.3).

The test files are the changed test files and the owned ones; an ID counts in its exact form
(`AC-T002-1`) or with underscores (`ac_t002_1`, so it can name a test function). The report
is read only from the aipm-generated `{report_file}` of the gate that wrote one (the `unit`
gate), never from the work tree. A test file "ran" when the report has a case from it that ran.
"""

import os
import re
import stat
import time

from aipm.domain.models import GateFinding, GateStatus, Severity
from aipm.gates.builtin import BuiltinOutcome, outcome
from aipm.gates.context import GateContext, test_files
from aipm.gates.reports import TestReport

NAME = "ac_trace"
MAX_TEST_FILE = 1_048_576


def id_pattern(criterion: str) -> re.Pattern[str]:
    """`AC-T002-1` in either spelling, not as part of a longer ID."""
    _, task, number = criterion.split("-")
    return re.compile(rf"(?i)(?<![A-Za-z0-9])AC[-_]{task}[-_]{number}(?![A-Za-z0-9])")


def _read(ctx: GateContext, rel: str) -> str:
    try:
        fd = os.open(ctx.root / rel, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    except OSError:
        return ""
    if not stat.S_ISREG(os.fstat(fd).st_mode):
        os.close(fd)
        return ""
    with os.fdopen(fd, "rb") as handle:
        return handle.read(MAX_TEST_FILE).decode("utf-8", errors="replace")


def ran(path: str, report: TestReport) -> bool:
    """Whether the report has a case from this test file that ran."""
    module = path.removesuffix(".py").replace("/", ".")
    for case in report.ran:
        loc = case.location
        if loc == path or loc.endswith(f"/{path}") or loc == module or loc.startswith(f"{module}."):
            return True
    return False


def run(ctx: GateContext, report: TestReport | None, *, required: bool) -> BuiltinOutcome:
    """Trace each acceptance criterion to a test that ran."""
    started = time.monotonic()
    if report is None:
        summary = "no test report: the unit gate did not run, or ran without {report_file}"
        return outcome(NAME, GateStatus.FAIL, summary, required=required, started=started)
    files = test_files(ctx)
    texts = {rel: _read(ctx, rel) for rel in files}
    missing: list[GateFinding] = []
    for criterion in ctx.task.acceptance:
        pattern = id_pattern(criterion.id)
        holders = [rel for rel, text in texts.items() if pattern.search(text)]
        if not holders:
            detail = "appears in no owned or changed test file"
        elif not any(ran(rel, report) for rel in holders):
            detail = f"its test file(s) did not run: {', '.join(holders[:3])}"
        else:
            continue
        missing.append(GateFinding(tool="ac_trace", rule=criterion.id, severity=Severity.HIGH,
                                   message=f"{criterion.id} {detail}"[:500]))  # fmt: skip
    if missing:
        return outcome(NAME, GateStatus.FAIL, f"{len(missing)} criterion(s) not traced",
                       required=required, started=started, findings=missing)  # fmt: skip
    count = len(ctx.task.acceptance)
    return outcome(NAME, GateStatus.PASS, f"{count} criterion(s) traced to tests that ran",
                   required=required, started=started)  # fmt: skip
