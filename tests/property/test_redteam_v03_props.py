"""Red-team fuzzing for v0.3 (build prompt 09; docs/security/reviews/v0.3.md).

Like the earlier properties, these take their example count from the active Hypothesis profile:
`pytest --hypothesis-profile=ci-long` runs each one at least 2,000 times. The strategies add
what the v0.3 pass attacked: ownership globs that look disjoint (case, Unicode normalization),
the agent's final message and stream-json output, budget holds under parallel scheduling, run
journals, the agent's sandbox profile, and the gate words that become `--allowedTools` rules.

Oracles restate their rule instead of calling the code under test.
"""

import json
import math
import os
import re
import tempfile
import unicodedata
from datetime import UTC, datetime
from pathlib import Path

from hypothesis import HealthCheck, given, settings
from hypothesis import strategies as st

from aipm.adapters.claude_code import (
    MAX_QUESTION,
    SESSION_ID,
    ClaudeCodeAdapter,
    allowed_tools,
    blocked_question,
)
from aipm.domain.dag import globs_may_overlap
from aipm.domain.errors import BudgetExceeded, PolicyViolation
from aipm.domain.models import JournalEvent, JournalEventType, NetworkProfile
from aipm.execution.journal import replay
from aipm.execution.process import ProcessResult
from aipm.execution.sandbox import ProcessKind, ProfilePaths, main_repo_entries, profile_for
from aipm.security.budget import RunBudget, Spend
from aipm.security.diff_checks import glob_match
from aipm.security.network import NetworkPolicy

# ---------------------------------------------------------------- the scheduler

E_NFC = "\u00e9"
E_NFD = "e\u0301"
COMPONENT = st.sampled_from(
    ["src", "SRC", "a", "A", "ab", "aB", "x.py", "X.PY", f"{E_NFC}.py", f"{E_NFD}.py", "lib"]
)
GLOB_PART = st.one_of(COMPONENT, st.sampled_from(["*", "a*", "*.py", "?b", "**"]))


def _fold(text: str) -> str:
    """How a case-insensitive, normalization-insensitive file system (APFS) compares names."""
    return unicodedata.normalize("NFC", text).casefold()


@given(
    st.lists(GLOB_PART, min_size=1, max_size=4),
    st.lists(GLOB_PART, min_size=1, max_size=4),
    st.lists(st.lists(COMPONENT, min_size=1, max_size=4), min_size=1, max_size=12),
)
def test_globs_the_scheduler_runs_together_never_share_a_file(
    a: list[str], b: list[str], paths: list[list[str]]
) -> None:
    """Two ownership globs `globs_may_overlap` calls disjoint match no common file, where the
    same file may be spelled in another case or Unicode normalization (macOS)."""
    ga, gb = "/".join(a), "/".join(b)
    if any("**" in p and p != "**" for p in (*a, *b)):
        return
    if globs_may_overlap(ga, gb):
        return
    for parts in paths:
        path = _fold("/".join(parts))
        assert not (glob_match(path, _fold(ga)) and glob_match(path, _fold(gb))), (ga, gb, path)


@st.composite
def respelled(draw: st.DrawFn) -> tuple[str, str]:
    """An ownership glob, and the same glob with some components in another case or Unicode
    normalization: a different string naming the same files on macOS."""
    parts = draw(st.lists(GLOB_PART, min_size=1, max_size=4))
    other: list[str] = []
    for part in parts:
        how = draw(st.sampled_from(["same", "swapcase", "nfd", "nfc"]))
        form = {"same": part, "swapcase": part.swapcase(),
                "nfd": unicodedata.normalize("NFD", part),
                "nfc": unicodedata.normalize("NFC", part)}[how]  # fmt: skip
        other.append(form)
    return "/".join(parts), "/".join(other)


@given(respelled())
def test_globs_that_name_the_same_files_always_conflict(pair: tuple[str, str]) -> None:
    """Red-team v0.3: `src/é.py` in NFC and in NFD looked disjoint, so two tasks owning one
    macOS file ran at the same time."""
    a, b = pair
    if any("**" in p and p != "**" for p in [*a.split("/"), *b.split("/")]):
        return
    assert globs_may_overlap(a, b), (a, b)


# ---------------------------------------------------------------- the agent's output

_INVISIBLE = re.compile(
    "[\u200b-\u200f\u202a-\u202e\u2060-\u2064\u2066-\u2069\ufeff\U000e0000-\U000e007f]"
)


@given(st.text(max_size=2000))
def test_a_blocked_question_is_one_clean_short_line(text: str) -> None:
    question = blocked_question(text)
    if question is None:
        return
    assert 0 < len(question) <= MAX_QUESTION
    assert not any(unicodedata.category(ch) in ("Cc", "Cf", "Zl", "Zp") for ch in question)
    assert not _INVISIBLE.search(question)
    assert question == question.strip()


@given(
    st.lists(
        st.one_of(
            st.binary(max_size=200),
            st.builds(
                lambda total, sid, text: json.dumps(
                    {
                        "type": "result",
                        "subtype": "success",
                        "is_error": False,
                        "total_cost_usd": total,
                        "session_id": sid,
                        "result": text,
                    }
                ).encode(),
                st.one_of(st.floats(allow_nan=True, allow_infinity=True), st.integers(), st.none()),
                st.one_of(st.uuids().map(str), st.text(max_size=40)),
                st.text(max_size=200),
            ),
        ),
        max_size=6,
    )
)
def test_any_agent_output_parses_to_a_bounded_result(lines: list[bytes]) -> None:
    stdout = b"\n".join(lines)
    out = ProcessResult(("claude",), 0, stdout, b"", timed_out=False, truncated=False,
                        duration_s=1.0)  # fmt: skip
    parsed = ClaudeCodeAdapter().parse_result(out)
    if parsed.cost_usd is not None:
        assert math.isfinite(parsed.cost_usd) and parsed.cost_usd >= 0
    if parsed.session_id is not None:
        assert SESSION_ID.fullmatch(parsed.session_id)
    if parsed.cost_usd is not None:
        for line in stdout.splitlines():
            total = _result_total(line)
            assert total is None or parsed.cost_usd >= total, "a forged line lowered the cost"


def _result_total(line: bytes) -> float | None:
    """The finite, non-negative total of a `result` event line, else `None`."""
    try:
        data = json.loads(line)
    except ValueError:
        return None
    if not isinstance(data, dict) or data.get("type") != "result":
        return None
    total = data.get("total_cost_usd")
    if isinstance(total, bool) or not isinstance(total, int | float):
        return None
    return float(total) if math.isfinite(total) and total >= 0 else None


# ---------------------------------------------------------------- budgets

OPERATION = st.one_of(
    st.tuples(st.just("schedule"), st.integers(1, 4)),
    st.tuples(st.just("start"), st.integers(1, 4)),
    st.tuples(st.just("settle"), st.integers(1, 4), st.floats(0, 5)),
    st.tuples(st.just("release"), st.integers(1, 4)),
)


@given(st.floats(0.1, 10), st.floats(0.1, 10), st.lists(OPERATION, max_size=40))
def test_no_hold_is_granted_past_the_run_budget(
    run_usd: float, task_usd: float, operations: list[tuple[object, ...]]
) -> None:
    """However tasks are scheduled, started, settled and released, a hold is granted only when
    the spend so far plus every hold fits in `run_usd`."""
    spend = Spend(RunBudget.of(run_usd=run_usd, task_usd=task_usd, run_tokens=10))
    attempt = 0
    for op in operations:
        kind, task = op[0], f"T-{op[1]:03d}"
        try:
            if kind == "schedule":
                spend.reserve(f"{task}/scheduled")
            elif kind == "start":
                attempt += 1
                spend.reserve(f"{task}/{attempt}", held=f"{task}/scheduled")
            elif kind == "settle":
                for key in [k for k in spend.reserved if k.startswith(f"{task}/")
                            and not k.endswith("scheduled")]:  # fmt: skip
                    spend.settle(key, float(op[2]))  # type: ignore[arg-type]
            else:
                spend.release(f"{task}/scheduled")
        except BudgetExceeded:
            continue
        if kind in ("schedule", "start"):
            assert spend.spent_usd + spend.reserved_usd <= run_usd + 1e-6


@given(
    st.lists(
        st.tuples(
            st.sampled_from(list(JournalEventType)),
            st.one_of(st.none(), st.sampled_from(["T-001", "T-002", "T-003"])),
            st.one_of(st.none(), st.integers(0, 100)),
            st.dictionaries(
                st.sampled_from(["cost_usd", "commit", "task_usd", "kind", "base", "integration"]),
                st.one_of(
                    st.floats(allow_nan=True),
                    st.integers(),
                    st.text(max_size=70),
                    st.booleans(),
                    st.none(),
                ),
                max_size=4,
            ),
        ),
        max_size=30,
    )
)
def test_any_journal_replays_to_a_bounded_spend(
    raw: list[tuple[JournalEventType, str | None, int | None, dict[str, object]]],
) -> None:
    events = [
        JournalEvent.model_validate(
            {
                "seq": n,
                "ts": datetime.now(UTC),
                "run": "r-20261112-1200-ab12",
                "type": kind,
                "task": task,
                "attempt": attempt,
                "data": data,
            }
        )
        for n, (kind, task, attempt, data) in enumerate(raw)
    ]
    state = replay("r-20261112-1200-ab12", events)
    assert math.isfinite(state.spent_usd) and state.spent_usd >= 0
    started = sum(1 for e in events if e.type is JournalEventType.AGENT_STARTED)
    finished = sum(1 for e in events if e.type is JournalEventType.AGENT_FINISHED)
    if started > finished and state.task_usd > 0:
        assert state.spent_usd > 0, "an agent that never finished is charged"


# ---------------------------------------------------------------- the agent's sandbox

NAMES = st.sampled_from([".env", "src", "secrets", "id_rsa", "notes.md", ".pm", "Library",
                         "node_modules", ".venv"])  # fmt: skip


@settings(suppress_health_check=[HealthCheck.too_slow])
@given(st.sets(NAMES, min_size=1, max_size=6), st.booleans())
def test_the_agent_profile_hides_the_main_repository_but_not_its_own_paths(
    names: set[str], home_is_repo: bool
) -> None:
    with tempfile.TemporaryDirectory() as scratch:
        base = Path(os.path.realpath(scratch))
        repo = base / "home" if home_is_repo else base / "repo"
        (repo / ".git").mkdir(parents=True)
        for name in names:
            (repo / name).mkdir(exist_ok=True)
        home = repo if home_is_repo else base / "home"
        worktree = home / "Library" / "Caches" / "aipm" / "worktrees" / "r" / "T-001"
        config_home = home / "Library" / "Caches" / "aipm" / "agents" / "r" / "run" / "T-001"
        temp = base / "tmp" / "agent"
        for path in (worktree, config_home, temp):
            path.mkdir(parents=True, exist_ok=True)
        keep = (worktree, temp, config_home)
        main = main_repo_entries(repo, keep=keep)
        paths = ProfilePaths(workspace=worktree, temp_dir=temp, home=home,
                             config_home=config_home, extra_deny_read=main)  # fmt: skip
        profile = profile_for(ProcessKind.AGENT, NetworkPolicy(NetworkProfile.NONE), paths,
                              runtime="srt")  # fmt: skip
        deny = [str(p) for p in profile.deny_read]
        for writable in profile.allow_write:
            for denied in deny:
                assert not str(writable).startswith(denied.rstrip("/") + "/"), (writable, denied)
                assert str(writable) != denied
        for name in names:
            entry = str(repo / name)
            holds_own = any(str(k).startswith(entry + "/") for k in keep)
            assert holds_own or entry in deny, name
        assert str(repo / ".git") not in deny


# ---------------------------------------------------------------- --allowedTools

WORD = st.text(
    alphabet=st.sampled_from([*"abcXYZ019._/@:+=-", " ", ",", "(", ")", "*", "$", "\n"]),
    min_size=1,
    max_size=12,
)


@given(st.lists(st.lists(WORD, min_size=1, max_size=4), max_size=4))
def test_gate_words_become_rules_that_allow_only_themselves(commands: list[list[str]]) -> None:
    try:
        rules = allowed_tools(commands)
    except PolicyViolation:
        assert any(not re.fullmatch(r"[A-Za-z0-9._/@:+=-]+", w) for argv in commands for w in argv)
        return
    parts = rules.split(",")
    assert parts[:5] == ["Read", "Edit", "Write", "Glob", "Grep"]
    for rule in parts[5:]:
        assert re.fullmatch(r"Bash\([A-Za-z0-9._/@:+= -]+?( \*)?\)", rule), rule
