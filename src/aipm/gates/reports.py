"""Test reports from `{report_file}`: JUnit XML (pytest) and the jest/vitest JSON reporter.

The report is T2: test code the agent wrote runs while it is written. aipm reads it only from the
path it generated in the attempt's private temp dir, deleted just before the gate runs (SECURITY
§10 rule 5), never from the work tree. XML with a DOCTYPE or an entity declaration is refused
before it is parsed, and every report is capped.
"""

import json
import os
import re
import stat
import xml.etree.ElementTree as ET
from dataclasses import dataclass
from enum import StrEnum
from pathlib import Path
from typing import Any, cast

MAX_REPORT_BYTES = 16 * 1_048_576
MAX_CASES = 50_000
_DTD = re.compile(rb"<!\s*(?:DOCTYPE|ENTITY)", re.IGNORECASE)


class CaseStatus(StrEnum):
    """How one test case ended."""

    PASSED = "passed"
    FAILED = "failed"
    SKIPPED = "skipped"


@dataclass(frozen=True, slots=True)
class TestCase:
    """One test case: where it lives (a module path or a file), its name, and how it ended."""

    __test__ = False  # not a pytest class

    location: str
    name: str
    status: CaseStatus


@dataclass(frozen=True, slots=True)
class TestReport:
    """Every test case in a report."""

    __test__ = False

    cases: tuple[TestCase, ...]

    @property
    def ran(self) -> list[TestCase]:
        """The cases that ran (passed or failed)."""
        return [c for c in self.cases if c.status is not CaseStatus.SKIPPED]

    @property
    def failed(self) -> list[TestCase]:
        """The cases that failed or errored."""
        return [c for c in self.cases if c.status is CaseStatus.FAILED]

    def summary(self) -> str:
        """`N passed, N failed, N skipped`."""
        counts = {s: sum(1 for c in self.cases if c.status is s) for s in CaseStatus}
        return ", ".join(f"{counts[s]} {s.value}" for s in CaseStatus)


class ReportError(ValueError):
    """The report is missing, too large, or not a format aipm reads."""


def read_report_file(path: Path) -> bytes:
    """The report's bytes: a regular file, opened without following a link, capped."""
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    except OSError:
        raise ReportError("the gate wrote no test report") from None
    if not stat.S_ISREG(os.fstat(fd).st_mode):
        os.close(fd)
        raise ReportError("the test report is not a regular file")
    with os.fdopen(fd, "rb") as handle:
        data = handle.read(MAX_REPORT_BYTES + 1)
    if len(data) > MAX_REPORT_BYTES:
        raise ReportError("the test report is larger than aipm reads")
    return data


def _junit_case(element: ET.Element) -> TestCase:
    location = element.get("file") or element.get("classname") or ""
    tags = {child.tag for child in element}
    if tags & {"failure", "error"}:
        status = CaseStatus.FAILED
    elif "skipped" in tags:
        status = CaseStatus.SKIPPED
    else:
        status = CaseStatus.PASSED
    return TestCase(
        location=location[:1024], name=(element.get("name") or "")[:1024], status=status
    )


def parse_junit(data: bytes) -> TestReport:
    """A JUnit XML report (pytest `--junitxml`)."""
    try:
        data.decode("utf-8")
    except UnicodeDecodeError:
        raise ReportError("the test report is not UTF-8") from None
    if _DTD.search(data):
        raise ReportError("the test report declares a DOCTYPE or an entity")
    try:
        root = ET.fromstring(data)  # noqa: S314 - no DTD can reach the parser
    except ET.ParseError:
        raise ReportError("the test report is not valid XML") from None
    if root.tag not in ("testsuites", "testsuite"):
        raise ReportError("the test report is not a JUnit report")
    cases = [_junit_case(e) for e in root.iter("testcase")]
    if len(cases) > MAX_CASES:
        raise ReportError("the test report has more cases than aipm reads")
    return TestReport(tuple(cases))


_JEST_STATUS = {
    "passed": CaseStatus.PASSED,
    "failed": CaseStatus.FAILED,
    "pending": CaseStatus.SKIPPED,
    "skipped": CaseStatus.SKIPPED,
    "todo": CaseStatus.SKIPPED,
    "disabled": CaseStatus.SKIPPED,
    "focused": CaseStatus.PASSED,
}


def parse_jest(data: bytes) -> TestReport:
    """A jest or vitest JSON report (`--json --outputFile`, `--reporter=json`)."""
    try:
        doc = json.loads(data)
    except (ValueError, RecursionError):
        raise ReportError("the test report is not valid JSON") from None
    data_doc = cast("dict[str, Any]", doc) if isinstance(doc, dict) else {}
    suites = data_doc.get("testResults")
    if not isinstance(suites, list):
        raise ReportError("the test report is not a jest or vitest report")
    cases: list[TestCase] = []
    for suite in cast("list[object]", suites):
        if not isinstance(suite, dict):
            continue
        entry = cast("dict[str, Any]", suite)
        location = entry.get("name") if isinstance(entry.get("name"), str) else ""
        results = entry.get("assertionResults")
        for item in cast("list[object]", results) if isinstance(results, list) else []:
            if not isinstance(item, dict):
                continue
            case = cast("dict[str, Any]", item)
            title = case.get("fullName") or case.get("title") or ""
            status = _JEST_STATUS.get(str(case.get("status")), CaseStatus.FAILED)
            cases.append(TestCase(str(location)[:1024], str(title)[:1024], status))
        if entry.get("status") == "failed" and not results:
            cases.append(TestCase(str(location)[:1024], "(suite)", CaseStatus.FAILED))
    if len(cases) > MAX_CASES:
        raise ReportError("the test report has more cases than aipm reads")
    return TestReport(tuple(cases))


def parse_report(data: bytes) -> TestReport:
    """Either format, told apart by its first byte."""
    head = data.lstrip()[:1]
    return parse_jest(data) if head == b"{" else parse_junit(data)


def load_report(path: Path) -> TestReport:
    """Read and parse the report at the aipm-generated `{report_file}` path."""
    return parse_report(read_report_file(path))
