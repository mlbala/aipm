"""Scanner wrappers (ARCHITECTURE §13.3): staged copies, fixed argv, normalized findings.

A repository cannot mute a scanner: links are never followed into the staged copy, scanner
configuration is never staged, and the argv names aipm's own settings. A missing scanner is
`skipped` and a broken one `error`; neither passes. The stubs in `tests/fakes/bin` imitate each
tool's flags and JSON report.
"""

import json
import os
from pathlib import Path

import pytest

from aipm.domain.errors import PolicyViolation
from aipm.domain.models import Severity
from aipm.execution.process import ProcessResult
from aipm.scanners import base, gitleaks, osv, semgrep, trivy
from aipm.scanners.base import ScanContext, ScanStatus, severity_of, stage_files
from aipm.security.redact import Redactor

STUB_BIN = Path(__file__).resolve().parents[1] / "fakes" / "bin"


@pytest.fixture
def stubs(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("PATH", f"{STUB_BIN}:/usr/bin:/bin")


@pytest.fixture
def no_tools(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    empty = tmp_path / "empty-bin"
    empty.mkdir()
    monkeypatch.setenv("PATH", str(empty))


def ctx(tmp_path: Path, repo: Path) -> ScanContext:
    temp = tmp_path / "attempt"
    temp.mkdir(mode=0o700, exist_ok=True)
    return ScanContext(repo=repo, temp_dir=temp, redactor=Redactor({}))


def repo_with(tmp_path: Path, files: dict[str, str]) -> Path:
    repo = tmp_path / "repo"
    for rel, body in files.items():
        (repo / rel).parent.mkdir(parents=True, exist_ok=True)
        (repo / rel).write_text(body, encoding="utf-8")
    repo.mkdir(exist_ok=True)
    return repo


# ---------------------------------------------------------------- staging


def test_staging_copies_regular_files_only(tmp_path: Path) -> None:
    secret = tmp_path / "outside-secret"
    secret.write_text("ssh key", encoding="utf-8")
    repo = repo_with(tmp_path, {"src/a.py": "x = 1\n", ".gitleaks.toml": "[allowlist]\n",
                                "src/.semgrepignore": "*\n", "big.bin": "x" * 50})  # fmt: skip
    (repo / "src" / "key").symlink_to(secret)
    (repo / "linkdir").symlink_to(tmp_path)
    os.mkfifo(repo / "fifo")
    paths = ["src/a.py", ".gitleaks.toml", "src/.semgrepignore", "src/key",
             "linkdir/outside-secret", "fifo", "missing.py", "../escape", "big.bin"]  # fmt: skip
    stage = stage_files(repo, paths, tmp_path / "stage")
    assert stage.files == ("big.bin", "src/a.py")
    assert sorted(p.relative_to(stage.root).as_posix() for p in stage.root.rglob("*")
                  if p.is_file()) == ["big.bin", "src/a.py"]  # fmt: skip
    assert oct(stage.root.stat().st_mode & 0o777) == "0o700"


def test_staging_marks_oversized_files(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    repo = repo_with(tmp_path, {"big.py": "x" * 100, "small.py": "y"})
    monkeypatch.setattr(base, "MAX_FILE_BYTES", 10)
    stage = stage_files(repo, ["big.py", "small.py"], tmp_path / "stage")
    assert stage.files == ("small.py",)
    assert stage.too_large == ("big.py",)


def test_staging_stops_at_the_file_cap(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    repo = repo_with(tmp_path, {"a": "1", "b": "2", "c": "3"})
    monkeypatch.setattr(base, "MAX_STAGE_FILES", 2)
    stage = stage_files(repo, ["a", "b", "c"], tmp_path / "stage")
    assert stage.too_large == ("c",)


def test_a_parent_that_is_a_link_is_not_followed(tmp_path: Path) -> None:
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "x.py").write_text("eval(1)", encoding="utf-8")
    repo = repo_with(tmp_path, {"keep.py": "1"})
    (repo / "src").symlink_to(outside)
    stage = stage_files(repo, ["src/x.py"], tmp_path / "stage")
    assert stage.files == ()


# ---------------------------------------------------------------- tools


def test_a_tool_inside_the_repository_is_refused(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    repo = repo_with(tmp_path, {"bin/gitleaks": "#!/bin/sh\n"})
    (repo / "bin" / "gitleaks").chmod(0o755)
    monkeypatch.setenv("PATH", f"{repo / 'bin'}:/usr/bin:/bin")
    with pytest.raises(PolicyViolation, match="inside the repository"):
        gitleaks.scan(ctx(tmp_path, repo), ["a.py"])


@pytest.mark.parametrize(
    ("call", "name"),
    [
        (lambda c: gitleaks.scan(c, ["a.py"]), "gitleaks"),
        (lambda c: semgrep.scan(c, ["a.py"], configs=["p/python"]), "semgrep"),
        (lambda c: osv.scan(c, ["uv.lock"]), "osv-scanner"),
        (lambda c: trivy.scan(c, ["a.py"]), "trivy"),
    ],
)
def test_a_missing_scanner_is_skipped_with_a_hint(
    call: object, name: str, no_tools: None, tmp_path: Path
) -> None:
    result = call(ctx(tmp_path, repo_with(tmp_path, {"a.py": "1"})))  # type: ignore[operator]
    assert result.status is ScanStatus.SKIPPED
    assert result.reason.startswith(f"{name} is not installed: install ")


# ---------------------------------------------------------------- runs through the stubs


def test_gitleaks_finds_the_marker_with_aipm_s_own_settings(
    stubs: None, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    repo = repo_with(tmp_path, {"src/a.py": "token = 'FAKE-LEAK-FOR-TESTS'\n", "src/b.py": "1"})
    seen: list[list[str]] = []
    real = base.run_safe

    def spy(argv: list[str], **kw: object) -> ProcessResult:
        seen.append(list(argv))
        return real(argv, **kw)  # type: ignore[arg-type]

    monkeypatch.setattr(base, "run_safe", spy)
    result = gitleaks.scan(ctx(tmp_path, repo), ["src/a.py", "src/b.py"])
    assert result.status is ScanStatus.OK
    assert [(f.rule, f.path, f.severity) for f in result.findings] == [
        ("fake-token", "src/a.py", Severity.HIGH)
    ]
    argv = seen[0]
    assert argv[argv.index("--config") + 1].endswith("gitleaks.toml")
    assert "--redact" in argv
    assert Path(argv[argv.index("--gitleaks-ignore-path") + 1]).read_bytes() == b""


def test_gitleaks_refuses_to_pass_files_it_could_not_scan(
    stubs: None, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    repo = repo_with(tmp_path, {"big.py": "x" * 100})
    monkeypatch.setattr(base, "MAX_FILE_BYTES", 10)
    result = gitleaks.scan(ctx(tmp_path, repo), ["big.py"])
    assert result.status is ScanStatus.ERROR
    assert "too large" in result.reason


def test_semgrep_runs_pinned_packs_with_metrics_off(
    stubs: None, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    repo = repo_with(tmp_path, {"src/a.py": "eval(input())\n", "src/b.py": "x = 1\n"})
    seen: list[list[str]] = []
    real = base.run_safe

    def spy(argv: list[str], **kw: object) -> ProcessResult:
        seen.append(list(argv))
        return real(argv, **kw)  # type: ignore[arg-type]

    monkeypatch.setattr(base, "run_safe", spy)
    result = semgrep.scan(ctx(tmp_path, repo), ["src/a.py", "src/b.py"], configs=["p/python"])
    assert [(f.path, f.severity) for f in result.findings] == [("src/a.py", Severity.HIGH)]
    argv = seen[0]
    for flag in ("--metrics", "off", "--disable-version-check", "--disable-nosem", "p/python"):
        assert flag in argv
    assert "auto" not in argv


@pytest.mark.parametrize("configs", [[], ["auto"], ["https://evil.example/rules.yml"]])
def test_semgrep_needs_pinned_packs(stubs: None, tmp_path: Path, configs: list[str]) -> None:
    result = semgrep.scan(ctx(tmp_path, repo_with(tmp_path, {"a.py": "1"})), ["a.py"],
                          configs=configs)  # fmt: skip
    assert result.status is ScanStatus.ERROR


def test_semgrep_with_nothing_to_scan(stubs: None, tmp_path: Path) -> None:
    result = semgrep.scan(ctx(tmp_path, repo_with(tmp_path, {})), ["gone.py"], configs=["p/x"])
    assert (result.status, result.reason) == (ScanStatus.OK, "no files to scan")


def test_osv_reports_a_critical_advisory(stubs: None, tmp_path: Path) -> None:
    repo = repo_with(tmp_path, {"uv.lock": '[[package]]\nname = "vulnerable-pkg"\n',
                                "osv-scanner.toml": "[[IgnoredVulns]]\n"})  # fmt: skip
    result = osv.scan(ctx(tmp_path, repo), ["uv.lock", "osv-scanner.toml"])
    assert [(f.rule, f.severity, f.path) for f in result.findings] == [
        ("GHSA-fake-0001", Severity.CRITICAL, "uv.lock")
    ]
    assert "vulnerable-pkg@1.0.0" in result.findings[0].message
    clean = osv.scan(ctx(tmp_path, repo_with(tmp_path, {"uv.lock": "x"})), ["uv.lock"])
    assert (clean.status, clean.findings) == (ScanStatus.OK, ())


def test_osv_with_no_lockfile(stubs: None, tmp_path: Path) -> None:
    result = osv.scan(ctx(tmp_path, repo_with(tmp_path, {})), ["uv.lock"])
    assert result.reason == "no lockfiles to scan"


def test_trivy_reports_secrets(stubs: None, tmp_path: Path) -> None:
    repo = repo_with(tmp_path, {"a.env.example": "FAKE-LEAK-FOR-TESTS\n"})
    result = trivy.scan(ctx(tmp_path, repo), ["a.env.example"])
    assert [(f.tool, f.rule, f.path) for f in result.findings] == [
        ("trivy", "fake-token", "a.env.example")
    ]


def _broken(tmp_path: Path, name: str, body: str, monkeypatch: pytest.MonkeyPatch) -> None:
    bin_dir = tmp_path / "broken-bin"
    bin_dir.mkdir(exist_ok=True)
    tool = bin_dir / name
    tool.write_text(f"#!/bin/sh\n{body}\n", encoding="utf-8")
    tool.chmod(0o755)
    monkeypatch.setenv("PATH", f"{bin_dir}:/usr/bin:/bin")


@pytest.mark.parametrize(
    ("name", "body", "call"),
    [
        ("gitleaks", "exit 1", lambda c: gitleaks.scan(c, ["a.py"])),
        ("gitleaks", "exit 0", lambda c: gitleaks.scan(c, ["a.py"])),
        ("semgrep", "exit 2", lambda c: semgrep.scan(c, ["a.py"], configs=["p/python"])),
        ("semgrep", "exit 0", lambda c: semgrep.scan(c, ["a.py"], configs=["p/python"])),
        ("osv-scanner", "exit 127", lambda c: osv.scan(c, ["uv.lock"])),
        ("osv-scanner", "exit 1", lambda c: osv.scan(c, ["uv.lock"])),
        ("trivy", "exit 1", lambda c: trivy.scan(c, ["a.py"])),
        ("trivy", "exit 0", lambda c: trivy.scan(c, ["a.py"])),
    ],
)
def test_a_failing_scanner_or_a_missing_report_is_an_error(
    name: str, body: str, call: object, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _broken(tmp_path, name, body, monkeypatch)
    repo = repo_with(tmp_path, {"a.py": "1", "uv.lock": "x"})
    result = call(ctx(tmp_path, repo))  # type: ignore[operator]
    assert result.status is ScanStatus.ERROR


def test_osv_no_packages_is_clean(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    _broken(tmp_path, "osv-scanner", "exit 128", monkeypatch)
    result = osv.scan(ctx(tmp_path, repo_with(tmp_path, {"uv.lock": "x"})), ["uv.lock"])
    assert (result.status, result.reason) == (ScanStatus.OK, "no packages found")


def test_scanner_output_is_redacted(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    _broken(
        tmp_path, "gitleaks", "echo 'ghp_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa'; exit 3", monkeypatch
    )
    result = gitleaks.scan(ctx(tmp_path, repo_with(tmp_path, {"a.py": "1"})), ["a.py"])
    assert "ghp_aaaa" not in result.output
    assert "REDACTED" in result.output


def test_a_scanner_runs_in_the_sandbox_when_there_is_one(
    stubs: None, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    repo = repo_with(tmp_path, {"a.py": "eval(1)\n"})
    seen: list[dict[str, object]] = []
    real = base.run_safe

    def spy(argv: list[str], **kw: object) -> ProcessResult:
        seen.append({"argv": list(argv), **kw})
        return real(argv, **kw)  # type: ignore[arg-type]

    monkeypatch.setattr(base, "run_safe", spy)
    c = ScanContext(repo=repo, temp_dir=ctx(tmp_path, repo).temp_dir,
                    runtime=str(STUB_BIN / "srt"))  # fmt: skip
    result = semgrep.scan(c, ["a.py"], configs=["p/python"])
    assert result.findings
    profile = seen[0]["sandbox"]
    assert profile is not None
    assert profile.network.domains == ("semgrep.dev",)  # type: ignore[attr-defined]
    env = seen[0]["env"]
    assert isinstance(env, dict)
    assert env["HOME"].startswith(str(c.temp_dir))


# ---------------------------------------------------------------- parsers and severities


@pytest.mark.parametrize(
    ("value", "expected"),
    [("CRITICAL", Severity.CRITICAL), ("ERROR", Severity.HIGH), ("moderate", Severity.MEDIUM),
     ("WARNING", Severity.MEDIUM), ("INFO", Severity.LOW), ("9.8", Severity.CRITICAL),
     (7.5, Severity.HIGH), ("4.0", Severity.MEDIUM), ("0.0", Severity.LOW), ("", Severity.HIGH),
     (None, Severity.HIGH), ("weird", Severity.HIGH), (True, Severity.HIGH)],
)  # fmt: skip
def test_severities_map_and_unknown_counts_as_high(value: object, expected: Severity) -> None:
    assert severity_of(value) is expected


def test_parsers_reject_what_is_not_a_report() -> None:
    assert gitleaks.parse({"x": 1}) is None
    assert gitleaks.parse([1, {"File": 5}]) is not None
    assert semgrep.parse([], "") is None
    assert semgrep.parse({"results": "x"}, "") is None
    assert semgrep.parse({"results": [1, {"extra": "x", "start": 3}]}, "")[0].severity is (  # type: ignore[index]
        Severity.HIGH
    )
    assert osv.parse("x", "") is None
    assert osv.parse({"results": 3}, "") is None
    assert (
        trivy.parse(
            [],
        )
        is None
    )
    assert trivy.parse({"Results": [{"Misconfigurations": [
        {"ID": "DS001", "Severity": "LOW", "Title": "t", "CauseMetadata": {"StartLine": 4}}]}]}
    )[0].line == 4  # type: ignore[index]  # fmt: skip


def test_osv_severity_falls_back_to_the_advisory_word() -> None:
    report = {"results": [{"source": {"path": "/s/uv.lock"}, "packages": [
        {"package": {"name": "a", "version": "1"},
         "vulnerabilities": [{"id": "X-1", "database_specific": {"severity": "MODERATE"}},
                             {"id": "X-2"}],
         "groups": [{"ids": ["X-1"], "max_severity": ""}]}]}]}  # fmt: skip
    found = osv.parse(report, "/s")
    assert found is not None
    assert [(f.rule, f.severity, f.path) for f in found] == [
        ("X-1", Severity.MEDIUM, "uv.lock"),
        ("X-2", Severity.HIGH, "uv.lock"),
    ]


def test_read_report_refuses_oversized_and_invalid(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    path = tmp_path / "r.json"
    path.write_text(json.dumps([1]), encoding="utf-8")
    assert base.read_report(path) == [1]
    path.write_text("{nope", encoding="utf-8")
    assert base.read_report(path) is None
    monkeypatch.setattr(base, "MAX_REPORT_BYTES", 2)
    path.write_text("[1, 2, 3]", encoding="utf-8")
    assert base.read_report(path) is None
    assert base.read_report(tmp_path / "missing") is None


def test_findings_at_or_above_a_level() -> None:
    low = base.Finding("t", "r", Severity.LOW, "p", None, "m")
    high = base.Finding("t", "r", Severity.HIGH, "p", 3, "m")
    result = base.ScanResult("t", ScanStatus.OK, (low, high))
    assert result.at_least(Severity.MEDIUM) == [high]
    assert high.as_dict()["line"] == 3
