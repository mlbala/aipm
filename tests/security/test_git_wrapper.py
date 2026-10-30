"""The hardened git wrapper (SECURITY.md §11) and the change set it builds (ARCHITECTURE §12.4).

Every call carries the hardening options before the subcommand and a constructed environment;
diffs never run an external diff or textconv; a hook or a repository's own signing program
never runs during `commit`; the integrity hashes are compared before git starts at all.
"""

import dataclasses
import hashlib
import os
from pathlib import Path

import pytest

from aipm.domain.errors import ExitCode, PolicyViolation, UsageError
from aipm.domain.models import ChangeStatus
from aipm.execution import git
from aipm.execution.process import ProcessResult
from tests.conftest import FakeSecrets, run_git

HARDENED = ["-c", "core.hooksPath=/dev/null", "-c", "core.fsmonitor=false",
            "-c", "diff.external=", "-c", "core.pager=cat", "--no-pager"]  # fmt: skip


@pytest.fixture
def home(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    """A home whose global git config names an identity and nothing else."""
    path = tmp_path / "user-home"
    path.mkdir()
    (path / ".gitconfig").write_text(
        "[user]\n\tname = aipm owner\n\temail = owner@example.invalid\n", encoding="utf-8"
    )
    monkeypatch.setenv("HOME", str(path))
    monkeypatch.setenv("XDG_CONFIG_HOME", str(path / ".config"))
    return path


def _sha(text: str) -> str:
    return hashlib.sha256(text.encode()).hexdigest()


# ---------------------------------------------------------------- hardening of every call


@pytest.mark.parametrize(
    ("call", "needle"),
    [
        (lambda repo: git.diff_names(repo, "a" * 40), ["diff", "--no-ext-diff", "--no-textconv"]),
        (lambda repo: git.diff_stats(repo, "a" * 40), ["diff", "--no-ext-diff", "--no-textconv"]),
        (lambda repo: git.diff_text(repo, "a" * 40, ["x"], max_bytes=10), ["--no-textconv"]),
        (git.untracked, ["ls-files", "--others", "--exclude-standard"]),
        (git.ignored, ["ls-files", "--ignored", "--directory"]),
        (lambda repo: git.tree_entries(repo, "a" * 40), ["ls-tree", "-r", "-z"]),
        (git.status_porcelain_v2, ["status", "--porcelain=v2", "-z"]),
    ],
)
def test_every_call_is_hardened(
    call: object,
    needle: list[str],
    tmp_repo: Path,
    monkeypatch: pytest.MonkeyPatch,
    fake_secrets: FakeSecrets,
) -> None:
    seen: list[dict[str, object]] = []

    def fake_run(argv: list[str], **kwargs: object) -> ProcessResult:
        seen.append({"argv": argv, **kwargs})
        return ProcessResult(tuple(argv), 0, b"", b"", False, False, 0.01)

    monkeypatch.setattr(git, "run_safe", fake_run)
    call(tmp_repo)  # type: ignore[operator]
    argv = seen[0]["argv"]
    assert isinstance(argv, list)
    assert argv[1:10] == HARDENED
    for word in needle:
        assert word in argv
    env = seen[0]["env"]
    assert isinstance(env, dict)
    assert env["GIT_LITERAL_PATHSPECS"] == "1"
    assert env["GIT_CONFIG_NOSYSTEM"] == "1"
    fake_secrets.assert_absent(repr(env))


def test_output_that_was_cut_is_an_error(tmp_repo: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    def fake_run(argv: list[str], **_: object) -> ProcessResult:
        return ProcessResult(tuple(argv), 0, b"x\0", b"", False, True, 0.01)

    monkeypatch.setattr(git, "run_safe", fake_run)
    with pytest.raises(UsageError, match="larger than aipm reads"):
        git.untracked(tmp_repo)


def test_a_failing_call_names_git_s_first_line(
    tmp_repo: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    def fake_run(argv: list[str], **_: object) -> ProcessResult:
        return ProcessResult(tuple(argv), 128, b"", b"fatal: bad object\nmore\n", False, False, 0)

    monkeypatch.setattr(git, "run_safe", fake_run)
    with pytest.raises(UsageError, match="fatal: bad object") as info:
        git.diff_names(tmp_repo, "a" * 40)
    assert info.value.exit_code is ExitCode.USAGE


# ---------------------------------------------------------------- parsing


def test_status_v2_records_are_parsed() -> None:
    data = (
        b"1 .M N... 100644 100644 100644 " + b"a" * 40 + b" " + b"a" * 40 + b" src/a b.py\0"
        b"u UU N... 100644 100644 100644 100644 "
        + b"b" * 40
        + b" "
        + b"c" * 40
        + b" "
        + b"d" * 40
        + b" conflict.py\0"
        b"? new.py\0! build/\0? ../escape\0"
    )
    entries = git.parse_status_v2(data)
    assert [(e.kind, e.path) for e in entries] == [
        ("changed", "src/a b.py"),
        ("unmerged", "conflict.py"),
        ("untracked", "new.py"),
        ("ignored", "build/"),
        ("untracked", None),
    ]
    assert entries[0].xy == ".M"
    assert entries[0].modes == ("100644", "100644", "100644")


@pytest.mark.parametrize(
    "data", [b"2 R. N... x\0", b"1 .M short\0", b"u UU short\0", b"# branch.oid x\0"]
)
def test_status_records_aipm_cannot_read_are_refused(data: bytes) -> None:
    with pytest.raises(UsageError):
        git.parse_status_v2(data)


def test_name_status_and_numstat_are_parsed() -> None:
    names = git.parse_name_status(b"M\0a.py\0A\0b.py\0D\0c.py\0T\0d\0U\0e.py\0")
    assert names == [
        (ChangeStatus.MODIFIED, "a.py"),
        (ChangeStatus.ADDED, "b.py"),
        (ChangeStatus.DELETED, "c.py"),
        (ChangeStatus.TYPE_CHANGED, "d"),
        (ChangeStatus.MODIFIED, "e.py"),
    ]
    with pytest.raises(UsageError):
        git.parse_name_status(b"M\0")
    stats = git.parse_numstat(b"3\t1\ta.py\0-\t-\tlogo.png\0")
    assert [(s.path, s.added, s.deleted) for s in stats] == [
        ("a.py", 3, 1),
        ("logo.png", None, None),
    ]
    with pytest.raises(UsageError):
        git.parse_numstat(b"3 1 a.py\0")


@pytest.mark.parametrize(
    "raw", [b"\xff\xfe.py", b"/abs", b"a/../b", b"./a", b"a//b", b"", b"..", b"a/.."]
)
def test_names_aipm_cannot_trust_decode_to_none(raw: bytes) -> None:
    assert git._decode(raw) is None  # pyright: ignore[reportPrivateUsage]


@pytest.mark.parametrize("rev", ["--output=/tmp/x", "HEAD~1", "main", "ABCDEF1", "abc", "a" * 65])
def test_only_hex_revisions_or_head_are_accepted(rev: str, tmp_repo: Path) -> None:
    with pytest.raises(UsageError, match="not a commit id"):
        git.resolve_commit(tmp_repo, rev)


def test_a_short_revision_resolves(tmp_repo: Path) -> None:
    head = git.head_sha(tmp_repo)
    assert git.resolve_commit(tmp_repo, head[:10]) == head
    assert git.resolve_commit(tmp_repo, "HEAD") == head
    with pytest.raises(UsageError, match="not a commit in this repository"):
        git.resolve_commit(tmp_repo, "0" * 40)


def test_file_at_reads_the_blob_without_filters(tmp_repo: Path) -> None:
    head = git.head_sha(tmp_repo)
    assert git.file_at(tmp_repo, head, "README.md") == b"# sample project\n"
    assert git.file_at(tmp_repo, head, "missing.md") is None
    with pytest.raises(UsageError):
        git.read_object(tmp_repo, "not-an-id", max_bytes=10)


def test_diff_text_is_capped(tmp_repo: Path) -> None:
    head = git.head_sha(tmp_repo)
    (tmp_repo / "README.md").write_text("x\n" * 5000, encoding="utf-8")
    text, cut = git.diff_text(tmp_repo, head, ["README.md"], max_bytes=200)
    assert cut is True
    assert len(text) <= 200
    assert git.diff_text(tmp_repo, head, [], max_bytes=10) == ("", False)


# ---------------------------------------------------------------- commits never run hooks


def _hook(repo: Path, name: str, marker: Path) -> None:
    hook = repo / ".git" / "hooks" / name
    hook.parent.mkdir(exist_ok=True)
    hook.write_text(f"#!/bin/sh\necho ran > '{marker}'\n", encoding="utf-8")
    hook.chmod(0o755)


def test_commit_never_runs_a_hook_and_adds_trailers(
    tmp_repo: Path, tmp_path: Path, home: Path
) -> None:
    markers = [tmp_path / f"{name}.ran" for name in ("pre-commit", "commit-msg", "post-commit")]
    for name, marker in zip(("pre-commit", "commit-msg", "post-commit"), markers, strict=True):
        _hook(tmp_repo, name, marker)
    (tmp_repo / "src").mkdir()
    (tmp_repo / "src" / "a.py").write_text("x = 1\n", encoding="utf-8")
    (tmp_repo / "other.txt").write_text("left alone\n", encoding="utf-8")
    sha = git.commit(
        tmp_repo,
        ["src/a.py"],
        message="aipm: T-002 Slots",
        trailers=[("Aipm-Task", "T-002"), ("Aipm-Attempt", "1")],
    )
    assert sha == git.head_sha(tmp_repo)
    for marker in markers:
        assert not marker.exists(), marker.name
    body = run_git(tmp_repo, "log", "-1", "--format=%an <%ae>%n%B")
    assert body.startswith("aipm owner <owner@example.invalid>\naipm: T-002 Slots\n")
    assert "Aipm-Task: T-002\nAipm-Attempt: 1\n" in body
    files = run_git(tmp_repo, "show", "--name-only", "--format=", "HEAD").split()
    assert files == ["src/a.py"]
    assert "other.txt" in run_git(tmp_repo, "status", "--porcelain")


def test_commit_ignores_the_repository_s_own_signing_program(
    tmp_repo: Path, tmp_path: Path, home: Path
) -> None:
    marker = tmp_path / "gpg.ran"
    fake_gpg = tmp_path / "evil-gpg"
    fake_gpg.write_text(f"#!/bin/sh\necho ran > '{marker}'\nexit 1\n", encoding="utf-8")
    fake_gpg.chmod(0o755)
    run_git(tmp_repo, "config", "commit.gpgsign", "true")
    run_git(tmp_repo, "config", "gpg.program", str(fake_gpg))
    (tmp_repo / "a.py").write_text("x = 1\n", encoding="utf-8")
    git.commit(tmp_repo, ["a.py"], message="m", trailers=[])
    assert not marker.exists()
    assert git.signing_overrides(tmp_repo) == [
        "-c", "commit.gpgsign=false", "-c", "gpg.format=openpgp", "-c", "gpg.program=gpg",
        "-c", "gpg.ssh.program=ssh-keygen", "-c", "gpg.x509.program=gpgsm",
    ]  # fmt: skip


def test_signing_follows_the_global_config(tmp_repo: Path, home: Path) -> None:
    with (home / ".gitconfig").open("a", encoding="utf-8") as handle:
        handle.write("[gpg]\n\tprogram = /opt/gpg2\n")
    assert "gpg.program=/opt/gpg2" in git.signing_overrides(tmp_repo)


def test_commit_refuses_nothing_and_bad_trailers(tmp_repo: Path, home: Path) -> None:
    with pytest.raises(UsageError, match="nothing to commit"):
        git.commit(tmp_repo, [], message="m", trailers=[])
    with pytest.raises(UsageError, match="not a commit trailer"):
        git.commit(tmp_repo, ["README.md"], message="m", trailers=[("Bad Key", "x")])
    with pytest.raises(UsageError, match="not a commit trailer"):
        git.commit(tmp_repo, ["README.md"], message="m", trailers=[("Aipm-Task", "a\nb")])


def test_pathspec_magic_is_literal(tmp_repo: Path, home: Path) -> None:
    """`:(exclude)` or a glob in a path is a file name, never pathspec magic."""
    (tmp_repo / "a.py").write_text("1\n", encoding="utf-8")
    (tmp_repo / "b.py").write_text("2\n", encoding="utf-8")
    with pytest.raises(UsageError):
        git.commit(tmp_repo, ["*.py"], message="m", trailers=[])
    assert "a.py" in run_git(tmp_repo, "status", "--porcelain")


# ---------------------------------------------------------------- integrity


def test_integrity_watches_git_config_hooks_includes_and_agent_config(
    tmp_repo: Path, tmp_path: Path, home: Path
) -> None:
    included = tmp_path / "included.cfg"
    included.write_text("[core]\n", encoding="utf-8")
    with (tmp_repo / ".git" / "config").open("a", encoding="utf-8") as handle:
        handle.write(f'[include]\n\tpath = "{included}"\n')
    before = git.integrity_snapshot(tmp_repo, home)
    assert before[".git/hooks"] is not None
    assert f"include: {included}" in before
    assert git.compare(before, git.integrity_snapshot(tmp_repo, home)) == []

    included.write_text("[core]\n\tfsmonitor = /tmp/evil\n", encoding="utf-8")
    _hook(tmp_repo, "pre-commit", tmp_path / "m")
    (home / ".claude").mkdir()
    (home / ".claude" / "settings.json").write_text('{"hooks": {}}', encoding="utf-8")
    (tmp_repo / ".git" / "info").mkdir(exist_ok=True)
    (tmp_repo / ".git" / "info" / "attributes").write_text("* filter=x\n", encoding="utf-8")
    changed = git.compare(before, git.integrity_snapshot(tmp_repo, home))
    assert changed == sorted(
        [f"include: {included}", ".git/hooks", "~/.claude/settings.json", ".git/info/attributes"]
    )


def test_a_linked_work_tree_is_read_through_its_git_file(tmp_repo: Path, tmp_path: Path) -> None:
    other = tmp_path / "wt"
    run_git(tmp_repo, "worktree", "add", "-q", str(other), "-b", "side")
    dirs = git.git_dirs(other)
    assert dirs.dotgit_file == other / ".git"
    assert dirs.common_dir.resolve() == (tmp_repo / ".git").resolve()
    labels = git.integrity_snapshot(other, tmp_path)
    assert labels[".git (work tree file)"] is not None


def test_git_dirs_refuses_odd_dot_git(tmp_path: Path) -> None:
    with pytest.raises(UsageError, match="not a git work tree"):
        git.git_dirs(tmp_path)
    (tmp_path / ".git").write_text("nonsense\n", encoding="utf-8")
    with pytest.raises(UsageError, match="does not name"):
        git.git_dirs(tmp_path)
    (tmp_path / ".git").unlink()
    (tmp_path / ".git").symlink_to(tmp_path)
    with pytest.raises(PolicyViolation):
        git.git_dirs(tmp_path)


def test_hash_path_covers_files_links_dirs_and_modes(tmp_path: Path) -> None:
    f = tmp_path / "f"
    f.write_text("x", encoding="utf-8")
    plain = git.hash_path(f)
    f.chmod(0o755)
    assert git.hash_path(f) != plain
    link = tmp_path / "l"
    link.symlink_to("f")
    assert git.hash_path(link) != git.hash_path(f)
    d = tmp_path / "d"
    d.mkdir()
    empty = git.hash_path(d)
    (d / "x").write_text("1", encoding="utf-8")
    assert git.hash_path(d) != empty
    assert git.hash_path(tmp_path / "missing") is None
    fifo = tmp_path / "fifo"
    os.mkfifo(fifo)
    assert git.hash_path(fifo) is not None
    assert git.content_sha256(f) == hashlib.sha256(b"x").hexdigest()
    assert git.content_sha256(link) == "not a regular file"
    assert git.content_sha256(tmp_path / "missing") is None


# ---------------------------------------------------------------- change sets


def _inputs(repo: Path, home: Path, **kw: object) -> git.ChangeInputs:
    base = git.head_sha(repo)
    values: dict[str, object] = {
        "base_sha": base,
        "integrity": git.integrity_snapshot(repo, home),
        "files": git.snapshot_files(repo, base, watch_ignored=lambda _: True),
        "ledger": {},
    }
    values.update(kw)
    return git.ChangeInputs(**values)  # type: ignore[arg-type]


def _changes(repo: Path, home: Path, inputs: git.ChangeInputs) -> object:
    return git.change_set(
        repo,
        inputs,
        home=home,
        watch_ignored=lambda p: p.endswith(".env") or p.startswith("tests/"),
        wants_content=lambda p: p.startswith("tests/"),
    )


def test_a_moved_integrity_hash_stops_before_git_runs(
    tmp_repo: Path, home: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    inputs = _inputs(tmp_repo, home)
    with (tmp_repo / ".git" / "config").open("a", encoding="utf-8") as handle:
        handle.write("[core]\n\tfsmonitor = /tmp/evil-monitor\n")

    def no_git(*_: object, **__: object) -> ProcessResult:
        raise AssertionError("git ran after .git/config changed")

    monkeypatch.setattr(git, "run_safe", no_git)
    changes = git.change_set(
        tmp_repo, inputs, home=home, watch_ignored=lambda _: True, wants_content=lambda _: True
    )
    assert changes.integrity == (".git/config",)
    assert changes.complete is False
    assert changes.files == ()


def test_changes_since_the_snapshot(tmp_repo: Path, home: Path, tmp_path: Path) -> None:
    (tmp_repo / ".gitignore").write_text(".env\n", encoding="utf-8")
    (tmp_repo / "tests").mkdir()
    (tmp_repo / "tests" / "test_a.py").write_text("def test_a():\n    assert 1\n", encoding="utf-8")
    (tmp_repo / "gone.txt").write_text("bye\n", encoding="utf-8")
    run_git(tmp_repo, "add", "-A")
    run_git(tmp_repo, "commit", "-q", "-m", "base")
    (tmp_repo / "README.md").write_text("user's own edit\n", encoding="utf-8")  # dirty before
    (tmp_repo / "notes.txt").write_text("untracked before\n", encoding="utf-8")
    (tmp_repo / ".env").write_text("A=1\n", encoding="utf-8")
    inputs = _inputs(tmp_repo, home)

    (tmp_repo / "tests" / "test_a.py").write_text("def test_a():\n    pass\n", encoding="utf-8")
    (tmp_repo / "src.py").write_text("x = 1\n", encoding="utf-8")
    (tmp_repo / "gone.txt").unlink()
    (tmp_repo / "notes.txt").unlink()
    (tmp_repo / ".env").write_text("A=2\n", encoding="utf-8")
    (tmp_repo / "key").symlink_to(tmp_path / "home" / ".ssh")
    changes = _changes(tmp_repo, home, inputs)
    assert isinstance(changes, git.ChangeSet)  # type: ignore[attr-defined]
    by_path = {c.path: c for c in changes.files}
    assert set(by_path) == {"tests/test_a.py", "src.py", "gone.txt", "notes.txt", "key"}
    assert by_path["src.py"].status is ChangeStatus.ADDED
    assert by_path["gone.txt"].status is ChangeStatus.DELETED
    assert by_path["notes.txt"].status is ChangeStatus.DELETED
    test = by_path["tests/test_a.py"]
    assert test.status is ChangeStatus.MODIFIED
    assert test.before == "def test_a():\n    assert 1\n"
    assert test.after == "def test_a():\n    pass\n"
    assert by_path["src.py"].before is None
    link = by_path["key"]
    assert link.is_symlink and link.link_escapes
    assert changes.hidden == (".env",)
    assert changes.complete is True


def test_pm_writes_aipm_made_are_its_own(tmp_repo: Path, home: Path) -> None:
    (tmp_repo / ".pm").mkdir()
    (tmp_repo / ".pm" / "tasks.yaml").write_text("v: 1\n", encoding="utf-8")
    (tmp_repo / ".pm" / "approvals.yaml").write_text("a: 1\n", encoding="utf-8")
    run_git(tmp_repo, "add", "-A")
    run_git(tmp_repo, "commit", "-q", "-m", "pm")
    inputs = _inputs(tmp_repo, home)
    (tmp_repo / ".pm" / "tasks.yaml").write_text("v: 2\n", encoding="utf-8")
    (tmp_repo / ".pm" / "approvals.yaml").write_text("a: forged\n", encoding="utf-8")
    (tmp_repo / ".pm" / ".lock").write_text("123 now\n", encoding="utf-8")
    ledger = {".pm/tasks.yaml": _sha("v: 2\n")}
    changes = _changes(tmp_repo, home, dataclasses.replace(inputs, ledger=ledger))
    assert [c.path for c in changes.files] == [".pm/approvals.yaml"]  # type: ignore[attr-defined]


def test_too_many_changes_make_the_set_incomplete(
    tmp_repo: Path, home: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    inputs = _inputs(tmp_repo, home)
    for i in range(3):
        (tmp_repo / f"f{i}.txt").write_text("x", encoding="utf-8")
    monkeypatch.setattr(git, "MAX_CHANGES", 2)
    changes = _changes(tmp_repo, home, inputs)
    assert changes.complete is False  # type: ignore[attr-defined]
    assert len(changes.files) == 2  # type: ignore[attr-defined]


def test_content_over_the_budget_is_marked_truncated(
    tmp_repo: Path, home: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    inputs = _inputs(tmp_repo, home)
    (tmp_repo / "tests").mkdir()
    (tmp_repo / "tests" / "test_big.py").write_text("x" * 100, encoding="utf-8")
    (tmp_repo / "tests" / "test_next.py").write_text("y", encoding="utf-8")
    monkeypatch.setattr(git, "MAX_TOTAL_CONTENT", 50)
    monkeypatch.setattr(git, "MAX_CONTENT_BYTES", 50)
    changes = _changes(tmp_repo, home, inputs)
    by_path = {c.path: c for c in changes.files}  # type: ignore[attr-defined]
    assert by_path["tests/test_big.py"].truncated is True
    assert by_path["tests/test_next.py"].truncated is True
    assert by_path["tests/test_next.py"].after is None


def test_a_snapshot_with_too_many_files_is_refused(
    tmp_repo: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    for i in range(3):
        (tmp_repo / f"u{i}").write_text("x", encoding="utf-8")
    monkeypatch.setattr(git, "MAX_SNAPSHOT_FILES", 2)
    with pytest.raises(UsageError, match="more than 2"):
        git.snapshot_files(tmp_repo, git.head_sha(tmp_repo), watch_ignored=lambda _: True)


def test_a_snapshot_refuses_names_it_cannot_read(
    tmp_repo: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(git, "untracked", lambda _repo: [None])
    with pytest.raises(UsageError, match="cannot read"):
        git.snapshot_files(tmp_repo, git.head_sha(tmp_repo), watch_ignored=lambda _: True)


def test_unreadable_names_make_the_set_incomplete(
    tmp_repo: Path, home: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    inputs = _inputs(tmp_repo, home)
    real = git.listing
    monkeypatch.setattr(
        git,
        "listing",
        lambda repo, base: git.Listing(
            tracked=[(ChangeStatus.MODIFIED, None), *real(repo, base).tracked],
            untracked=[None],
            ignored_files=[None],
        ),
    )
    changes = _changes(tmp_repo, home, inputs)
    assert changes.complete is False  # type: ignore[attr-defined]


def test_a_symlink_onto_a_protected_path_is_flagged(tmp_repo: Path, home: Path) -> None:
    inputs = _inputs(tmp_repo, home)
    (tmp_repo / "agents").symlink_to("AGENTS.md")
    (tmp_repo / "AGENTS.md").write_text("x", encoding="utf-8")
    (tmp_repo / "root").symlink_to(".")
    changes = _changes(tmp_repo, home, inputs)
    by_path = {c.path: c for c in changes.files}  # type: ignore[attr-defined]
    assert by_path["agents"].link_protected is True
    assert by_path["agents"].link_escapes is False
    assert by_path["root"].link_escapes is True
