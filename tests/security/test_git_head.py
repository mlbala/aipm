"""`head_sha`: aipm's one git call in v0.1 (SECURITY.md §8, §10, §11).

It runs through `run_safe` with the hardening options before the subcommand (a repository's own
config cannot name hooks or an fsmonitor program), a constructed environment that carries no
secret, a timeout and an output cap.
"""

from pathlib import Path

import pytest

from aipm.domain.errors import ExitCode, MissingCapability, UsageError
from aipm.execution import git
from aipm.execution.process import ProcessResult
from tests.conftest import FakeSecrets


def test_head_sha_is_the_commit_of_head(tmp_repo: Path) -> None:
    sha = git.head_sha(tmp_repo)
    assert len(sha) == 40
    assert all(c in "0123456789abcdef" for c in sha)
    ref = (tmp_repo / ".git" / "HEAD").read_text(encoding="utf-8").split()[-1]
    assert (tmp_repo / ".git" / ref).read_text(encoding="utf-8").strip() == sha


def test_the_call_is_hardened_and_its_environment_constructed(
    tmp_repo: Path, monkeypatch: pytest.MonkeyPatch, fake_secrets: FakeSecrets
) -> None:
    seen: dict[str, object] = {}

    def fake_run(argv: list[str], **kwargs: object) -> ProcessResult:
        seen["argv"] = argv
        seen.update(kwargs)
        return ProcessResult(tuple(argv), 0, b"a" * 40 + b"\n", b"", False, False, 0.01)

    monkeypatch.setattr(git, "run_safe", fake_run)
    assert git.head_sha(tmp_repo) == "a" * 40
    argv = seen["argv"]
    assert isinstance(argv, list)
    assert Path(argv[0]).is_absolute()
    assert argv[1:6] == ["-c", "core.hooksPath=/dev/null", "-c", "core.fsmonitor=false",
                         "--no-pager"]  # fmt: skip
    assert argv[6:] == ["rev-parse", "--verify", "--quiet", "HEAD^{commit}"]
    env = seen["env"]
    assert isinstance(env, dict)
    assert env["GIT_TERMINAL_PROMPT"] == "0"
    fake_secrets.assert_absent(repr(env))
    assert seen["timeout_s"] == git.GIT_TIMEOUT_S


def test_a_repository_without_commits_exits_2(tmp_path: Path, tmp_repo: Path) -> None:
    empty = tmp_path / "empty"
    (empty / ".git").mkdir(parents=True)
    with pytest.raises(UsageError) as info:
        git.head_sha(empty)
    assert info.value.exit_code is ExitCode.USAGE


def test_odd_output_is_refused(tmp_repo: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    def fake_run(argv: list[str], **_: object) -> ProcessResult:
        return ProcessResult(tuple(argv), 0, b"--upload-pack=evil\n", b"", False, False, 0.0)

    monkeypatch.setattr(git, "run_safe", fake_run)
    with pytest.raises(UsageError):
        git.head_sha(tmp_repo)


def test_no_git_exits_8(tmp_repo: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(git.shutil, "which", lambda _name: None)
    with pytest.raises(MissingCapability) as info:
        git.head_sha(tmp_repo)
    assert info.value.exit_code is ExitCode.MISSING_TOOL
