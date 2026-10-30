"""Red-team fuzzing for v0.2 (build prompt 09; docs/security/reviews/v0.2.md).

Like the v0.1 properties, these take their example count from the active Hypothesis profile:
`pytest --hypothesis-profile=ci-long` runs each one at least 2,000 times. The strategies add
what the v0.2 pass attacked: git config syntax (git itself is the oracle for what it includes),
registry URLs with look-alike hosts and userinfo, requirement lines with paths and direct
references, hostile test reports, gate output with escapes and split secrets, the Claude
subagent and skill files with hostile fields, the attempt snapshot and write ledger, and the
post-change checks over random manifests and lockfiles.

Oracles restate their rule instead of calling the code under test, except where git is the
oracle for git's own syntax.
"""

import json
import os
from datetime import UTC, datetime
from pathlib import Path
from urllib.parse import urlsplit

import pytest
from hypothesis import HealthCheck, assume, given, settings
from hypothesis import strategies as st

from aipm.app.repo_map import ignore_spec
from aipm.config.schema import Config
from aipm.config.stacks import load_stack
from aipm.context.generator import claude_extras
from aipm.domain.errors import PolicyViolation, UsageError
from aipm.domain.models import (
    AcceptanceCriterion,
    ChangeSet,
    ChangeStatus,
    DependencyAdd,
    Ecosystem,
    FileChange,
    GateWorkspace,
    Task,
    TaskSize,
    TaskType,
)
from aipm.execution import git
from aipm.execution.process import ProcessResult
from aipm.gates.command_gate import _output  # pyright: ignore[reportPrivateUsage]
from aipm.gates.context import GateContext
from aipm.gates.reports import ReportError, TestReport, parse_report
from aipm.security.agent_text import agent_text_problems
from aipm.security.command_policy import check_argv
from aipm.security.diff_checks import CheckPolicy, check_changes, lock_deps, manifest_deps
from aipm.security.paths import denied_for_llm
from aipm.security.redact import Redactor
from aipm.state.attempts import WriteLedger, load_snapshot
from aipm.state.layout import repo_id
from aipm.state.private_files import state_dir
from tests.conftest import run_program
from tests.fakes.project import hostile_context
from tests.fakes.secrets import FAKE_SECRETS
from tests.property.test_redteam_v01_props import BASE_CONTEXT, FIELD

FUZZ = settings(deadline=None, suppress_health_check=[HealthCheck.too_slow])
HARD_DENIED = {"sh", "bash", "zsh", "curl", "wget", "env", "rm", "git", "npx", "uvx", "awk"}

# ---------------------------------------------------------------- git config syntax (RT02-7)

SECTION = st.sampled_from(
    ["[include]", "[INCLUDE]", '[includeIf "gitdir:/"]', '[includeIf "onbranch:]x"]', "[core]",
     "[include.sub]", "[include] ", "[filter \"x\"]", "[ include ]"]
)  # fmt: skip
KEY = st.sampled_from(["path", "PATH", "Path", "path ", "\tpath", "pathx", "excludesFile"])
VALUE = st.sampled_from(
    ["a.cfg", '"a b.cfg"', "a.cfg ; c", "a.cfg # c", '"x;y.cfg"', "a\\\\b.cfg", '"q\\"r.cfg"',
     "~/h.cfg", "/abs/x.cfg", "", " sp.cfg ", '"un', "x\\\n y.cfg"]
)  # fmt: skip
LINE = st.one_of(
    SECTION,
    st.builds(lambda k, v: f"{k} = {v}", KEY, VALUE),
    st.builds(lambda s, k, v: f"{s} {k} = {v}", SECTION, KEY, VALUE),
    st.sampled_from(["# comment", "; comment", "", "  ", "[", "]", "=x"]),
)
CONFIG = st.lists(LINE, max_size=10).map("\n".join)


@pytest.fixture(scope="module")
def config_file(tmp_path_factory: pytest.TempPathFactory) -> Path:
    return tmp_path_factory.mktemp("gitcfg") / "config"


def _git_includes(path: Path) -> set[str] | None:
    """What git itself reads as include paths in one file (no following), or `None` when git
    refuses the file."""
    env = {"PATH": os.environ["PATH"], "HOME": "/nonexistent", "GIT_CONFIG_NOSYSTEM": "1"}
    result = run_program(
        ["git", "config", "--file", str(path), "--no-includes", "--list", "-z"],
        env=env, cwd=path.parent,
    )  # fmt: skip
    if result.returncode != 0:
        return None
    found: set[str] = set()
    for item in result.stdout.split("\0"):
        key, _, value = item.partition("\n")
        if key == "include.path" or (key.startswith("includeif.") and key.endswith(".path")):
            found.add(value)
    return found


@FUZZ
@given(CONFIG)
def test_every_include_git_reads_is_one_aipm_watches(config_file: Path, text: str) -> None:
    config_file.write_text(text + "\n", encoding="utf-8")
    expected = _git_includes(config_file)
    assume(expected is not None)
    assert expected is not None
    found = {
        value
        for section, name, value in git.config_values(text + "\n")
        if section in ("include", "includeif") and name == "path"
    }
    assert expected <= found, (text, expected, found)


# ---------------------------------------------------------------- registry hosts (RT02-3)

URL = st.builds(
    lambda scheme, user, host, port, path: f"{scheme}{user}{host}{port}{path}",
    st.sampled_from(["https://", "http://", "HTTPS://", "git+https://", "", "file:"]),
    st.sampled_from(["", "registry.npmjs.org@", "u:p@"]),
    st.sampled_from(["registry.npmjs.org", "registry.npmjs.org.evil.example", "evil.example",
                     "registry.yarnpkg.com", "registry.npmjs.org\\", "REGISTRY.NPMJS.ORG"]),
    st.sampled_from(["", ":443", ":8080"]),
    st.sampled_from(["/", "/x/-/x-1.tgz", "", "?a=/", "#/"]),
)  # fmt: skip


@FUZZ
@given(URL)
def test_a_lockfile_source_passes_only_from_a_default_registry_host(url: str) -> None:
    doc = {"packages": {"node_modules/x": {"version": "1.0.0", "resolved": url}}}
    parsed = lock_deps("package-lock.json", json.dumps(doc))
    assert parsed is not None
    if not parsed.sources:
        split = urlsplit(url)
        assert split.scheme == "https", url
        assert split.netloc in ("registry.npmjs.org", "registry.yarnpkg.com"), url


# ---------------------------------------------------------------- requirement lines (RT02-2)

REQ_PIECE = st.sampled_from(
    ["requests", "./", "vendor/", "~/", "/", "evil", "-1.0", ".whl", ".tar.gz", ".zip", "@",
     " @ ", "file:", "https://", "evil.example/x", "[a]", ">=2", "==1", ";", " ", "--hash=x",
     "-e ", "-r ", "-c ", "--index-url ", "-i ", "--pre", "requirements-dev.txt", "#", "\\"]
)  # fmt: skip
REQ_LINE = st.lists(REQ_PIECE, min_size=1, max_size=8).map("".join)


@FUZZ
@given(REQ_LINE)
def test_a_requirement_aipm_reads_as_a_name_has_no_path_or_url(line: str) -> None:
    deps = manifest_deps("requirements.txt", line + "\n")
    assert deps is not None
    if deps.names:
        body = line.split(" #", 1)[0].split(" --hash", 1)[0].strip()
        head = body.split(";", 1)[0]
        assert "://" not in body and "@" not in head, line
        assert not body.startswith((".", "/", "~", "-")), line
        assert "/" not in head, line
        assert not head.rstrip().endswith((".whl", ".tar.gz", ".zip")), line


# ---------------------------------------------------------------- the deny list (RT02-5)

DENY_PATH = st.lists(
    st.sampled_from(["src", "Secrets.yaml", "server.PEM", ".ENV", ".env.local", "id_rsa",
                     "AWS_Credentials.json", "deploy.key", "notes.md", ".NPMRC", "a.p12",
                     "x.pfx", ".git", ".pm", "keys", "README", "my-secret-dir"]),
    min_size=1, max_size=4,
).map("/".join)  # fmt: skip


@FUZZ
@given(DENY_PATH)
def test_what_the_repo_map_withholds_the_reviewer_withholds_too(
    tmp_path_factory: pytest.TempPathFactory, path: str
) -> None:
    rules = ignore_spec(tmp_path_factory.getbasetemp())
    if rules.match_file(path):
        assert denied_for_llm(path), path


# ---------------------------------------------------------------- test reports

JUNIT = st.lists(
    st.sampled_from(
        ['<?xml version="1.0"?>', "<testsuites>", "</testsuites>", "<testsuite>", "</testsuite>",
         '<testcase classname="tests.t" name="x"/>', '<testcase name="y">', "</testcase>",
         "<failure/>", "<skipped/>", "<!DOCTYPE x>", '<!ENTITY a "b">', "&a;", "\x00", "\xff",
         "<!-- c -->", "<![CDATA[x]]>", "{", '{"testResults": [', "]}", '{"name": 1}', "null"]
    ),
    max_size=12,
).map("".join)  # fmt: skip


@FUZZ
@given(st.one_of(JUNIT.map(lambda s: s.encode("utf-8", "surrogatepass")), st.binary(max_size=64)))
def test_a_test_report_parses_or_is_refused(data: bytes) -> None:
    try:
        report = parse_report(data)
    except ReportError:
        return
    assert isinstance(report, TestReport)
    assert all(c.status.value in ("passed", "failed", "skipped") for c in report.cases)


# ---------------------------------------------------------------- gate output (I-5, I-6)

SECRET = next(iter(FAKE_SECRETS.values()))
OUTPUT_PIECE = st.sampled_from(
    [SECRET[:12], SECRET[12:], SECRET, "\x1b[31m", "\x1b]8;;https://evil.example\x07", "\x1b",
     "\x07", "\u200b", "\r", "\n", "ok", " ", "\x9b", "\x1b]52;c;ZXZpbA==\x07"]
)  # fmt: skip


@FUZZ
@given(st.lists(OUTPUT_PIECE, max_size=16).map("".join))
def test_gate_output_holds_no_escape_and_no_registered_secret(
    tmp_path_factory: pytest.TempPathFactory, text: str
) -> None:
    root = tmp_path_factory.getbasetemp()
    ctx = GateContext(
        ws=GateWorkspace(root=root, temp_dir=root, base_sha="a" * 40),
        task=Task(id="T-001", title="t", type=TaskType.FEATURE, size=TaskSize.S,
                  acceptance=[AcceptanceCriterion(id="AC-T001-1", text="x")]),
        cfg=Config(), changes=ChangeSet("a" * 40), redactor=Redactor(FAKE_SECRETS),
        home=root, now=datetime.now(UTC),
    )  # fmt: skip
    raw = text.encode("utf-8")
    out = _output(ProcessResult(("x",), 0, raw, raw, False, False, 0.0), ctx)
    assert "\x1b" not in out and "\x9b" not in out and "\x07" not in out
    for secret in FAKE_SECRETS.values():
        assert secret not in out


# ---------------------------------------------------------------- Claude subagents and skills (I-3)


@FUZZ
@given(FIELD)
def test_hostile_fields_make_clean_claude_extras(field: str) -> None:
    try:
        files = claude_extras(hostile_context(field, BASE_CONTEXT))
    except (PolicyViolation, UsageError):
        return
    for generated in files:
        assert agent_text_problems(generated.document, allowed_url_domains=()) == [], generated.path
        assert "<!--" not in generated.document


# ---------------------------------------------------------------- attempt snapshot and ledger

JSON_PIECE = st.sampled_from(
    ['{', '}', '"schema_version": 1', '"schema_version": 2', '"repo": "0123456789abcdef"',
     '"task": "T-001"', '"task": "../x"', '"base_sha": "' + "a" * 40 + '"',
     '"created_at": "2026-10-30T00:00:00Z"', '"created_at": "2026-13-45"', '"files": {}',
     '"files": {"a": "' + "b" * 64 + '"}', '"files": []', '"integrity": {"x": null}',
     '"extra": 1', ",", ":", "[", "]", "null", "1e999", '"\\u0000"']
)  # fmt: skip


@pytest.fixture(scope="module")
def private_repo(tmp_path_factory: pytest.TempPathFactory) -> Path:
    repo = tmp_path_factory.mktemp("snapshot-repo")
    (repo / ".git").mkdir()
    return repo


@FUZZ
@given(st.lists(JSON_PIECE, max_size=14).map("".join))
def test_a_damaged_snapshot_or_ledger_is_refused_never_read(
    private_repo: Path, monkeypatch_module: None, text: str
) -> None:
    del monkeypatch_module
    target = state_dir(private_repo) / "attempts" / repo_id(private_repo) / "T-001.json"
    target.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    target.write_text(text, encoding="utf-8")
    target.chmod(0o600)
    try:
        snapshot = load_snapshot(private_repo, "T-001")
    except PolicyViolation:
        snapshot = None
    if snapshot is not None:
        assert snapshot.task == "T-001" and snapshot.repo == repo_id(private_repo)
    ledger = WriteLedger(private_repo)
    ledger.path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    ledger.path.write_text(text, encoding="utf-8")
    ledger.path.chmod(0o600)
    try:
        files = ledger.load()
    except PolicyViolation:
        return
    assert all(isinstance(k, str) for k in files)


@pytest.fixture(scope="module")
def monkeypatch_module(tmp_path_factory: pytest.TempPathFactory) -> object:
    """The user state dir in a temp dir for the whole module (Hypothesis reuses fixtures)."""
    mp = pytest.MonkeyPatch()
    base = tmp_path_factory.mktemp("state")
    mp.setenv("HOME", str(base / "home"))
    mp.setenv("XDG_STATE_HOME", str(base / "state"))
    yield None
    mp.undo()


# ---------------------------------------------------------------- post-change checks

EVIL = "https://evil.example/x.tgz"
FORMATS: dict[str, list[str]] = {
    "pyproject.toml": ['[project]\ndependencies = ["requests>=2"]\n', "[x",
                       f'[project]\ndependencies = ["requests @ {EVIL}"]\n',
                       f'[tool.uv.sources]\nrequests = {{ url = "{EVIL}" }}\n'],
    "package.json": ['{"dependencies": {"lodash": "^4"}}', "{",
                     f'{{"dependencies": {{"lodash": "{EVIL}"}}}}'],
    "requirements.txt": ["requests==2\n", f"requests @ {EVIL}\n", f"--find-links {EVIL}\n"],
    "uv.lock": ['[[package]]\nname = "a"\nsource = { registry = "https://pypi.org/simple" }\n',
                f'[[package]]\nname = "a"\nsource = {{ url = "{EVIL}" }}\n', "[["],
    "package-lock.json": ['{"packages": {"node_modules/a": {"resolved": '
                          '"https://registry.npmjs.org/a/-/a-1.tgz"}}}',
                          f'{{"packages": {{"node_modules/a": {{"resolved": "{EVIL}"}}}}}}'],
    "pnpm-lock.yaml": ["packages:\n  a@1.0.0:\n    resolution: {integrity: x}\n",
                       f"packages:\n  a@1.0.0:\n    resolution: {{tarball: {EVIL}}}\n"],
    "yarn.lock": ['a@^1:\n  resolved "https://registry.yarnpkg.com/a/-/a-1.tgz"\n',
                  f'a@^1:\n  resolved "{EVIL}"\n'],
    ".npmrc": ["save-exact=true\n", f"registry={EVIL}\n"],
    "src/a.py": ["import os\n", f"URL = '{EVIL}'\n"],
}  # fmt: skip
CHANGE = st.sampled_from(sorted(FORMATS)).flatmap(
    lambda path: st.builds(
        lambda before, after, truncated: FileChange(
            path=path,
            status=ChangeStatus.MODIFIED,
            mode="100644",
            before=before,
            after=after,
            truncated=truncated,
        ),
        st.none() | st.sampled_from(FORMATS[path]),
        st.none() | st.sampled_from(FORMATS[path]),
        st.booleans(),
    )
)
TASK = Task(
    id="T-001", title="t", type=TaskType.FEATURE, size=TaskSize.S,
    owns_files=[p for p in FORMATS if p != "src/a.py"] + ["src/**"],
    acceptance=[AcceptanceCriterion(id="AC-T001-1", text="x")],
    deps_add=[DependencyAdd(ecosystem=Ecosystem.PYPI, name="requests")],
)  # fmt: skip


@FUZZ
@given(st.lists(CHANGE, max_size=5, unique_by=lambda c: c.path))
def test_the_checks_never_crash_and_flag_every_new_off_registry_source(
    changes: list[FileChange],
) -> None:
    found = check_changes(ChangeSet("a" * 40, files=tuple(changes)), TASK, CheckPolicy())
    assert found == check_changes(ChangeSet("a" * 40, files=tuple(changes)), TASK, CheckPolicy())
    flagged = {v.path for v in found if v.kind.value == "dependency"}
    for c in changes:
        added = c.after is not None and EVIL in c.after and EVIL not in (c.before or "")
        if added and c.path != "src/a.py":
            assert c.path in flagged, (c.path, c.before, c.after)
        if c.path == "src/a.py":
            assert c.path not in flagged


# ---------------------------------------------------------------- the v0.2 stack templates

STACK_ARGS = st.sampled_from(
    ["{paths}", "src/app.py", "--fix", "-e", "--eval", "-p", "-c", "bash", "/bin/SH", "curl",
     "env", "git", "npx", "uvx", "awk", "-m", "pip", "install", "--require", "./x.js", "-r",
     "requirements.txt", "--", "time", "zsh-5.9", "node22", "run", "exec", "dlx"]
)  # fmt: skip


@FUZZ
@given(st.sampled_from(["python-pip", "node-npm", "node-pnpm", "python-uv"]),
       st.integers(0, 4), st.lists(STACK_ARGS, max_size=6))  # fmt: skip
def test_a_stack_template_never_accepts_a_hard_denied_program(
    stack: str, index: int, args: list[str]
) -> None:
    policy = Config.model_validate(load_stack(stack).model_dump(mode="json")).command_policy()
    prefixes = list(policy.allowed_prefixes)
    prefix = list(prefixes[index % len(prefixes)])
    try:
        argv = check_argv((*prefix, *args), policy, stage="gate")
    except PolicyViolation:
        return
    names = {Path(a).name.casefold() for a in argv if a != "{paths}"}
    assert not names & HARD_DENIED, argv
