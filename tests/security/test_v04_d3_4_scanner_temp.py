"""The v0.4 decisions, session 5, item 4: a scanner's temp dir is `<out>/tmp`, not `<out>`.

srt sets the command's `TMPDIR` from `CLAUDE_CODE_TMPDIR`, which aipm sets to the profile's temp
dir. A built-in scanner set `TMPDIR=<out>/tmp` but got `<out>` from its profile, so under srt its
temp files went next to its report. `temp_env` now also accepts a temp dir *inside* an allowed
write path, on conditions that keep the sandbox from writing anywhere it could not before:
absolute, normalised, outside every denied path and pattern, and not reached through a link
below the allowed entry. An exact allow entry is accepted as before, so agents, gates and
prepare are unchanged.
"""

import dataclasses
from pathlib import Path

import pytest

from aipm.domain.errors import ExitCode, PolicyViolation
from aipm.execution.process import ProcessResult
from aipm.execution.sandbox import (
    TEMP_ENV,
    ProcessKind,
    ProfilePaths,
    SandboxProfile,
    profile_for,
    temp_env,
)
from aipm.scanners import base
from aipm.scanners.base import ScanContext, Tool, run_tool
from aipm.security.network import NetworkPolicy, NetworkProfile

NONE = NetworkPolicy(NetworkProfile.NONE)


def _profile(allow: Path, temp: Path, **extra: object) -> SandboxProfile:
    return SandboxProfile(
        ProcessKind.SCANNER, NONE, runtime="/bin/srt", settings_dir=allow,
        allow_write=(allow,), temp_dir=temp, **extra,  # type: ignore[arg-type]
    )  # fmt: skip


def _refused(profile: SandboxProfile) -> None:
    with pytest.raises(PolicyViolation, match="temp dir") as info:
        temp_env(profile)
    assert info.value.exit_code is ExitCode.SECURITY_VIOLATION


# ------------------------------------------------------------------ what temp_env accepts


def test_an_allow_entry_is_accepted(tmp_path: Path) -> None:
    out = tmp_path / "out"
    out.mkdir()
    assert temp_env(_profile(out, out)) == {TEMP_ENV: str(out)}


def test_a_sub_directory_of_an_allow_entry_is_accepted(tmp_path: Path) -> None:
    out = tmp_path / "out"
    (out / "tmp").mkdir(parents=True)
    assert temp_env(_profile(out, out / "tmp")) == {TEMP_ENV: str(out / "tmp")}


def test_a_sub_directory_that_does_not_exist_yet_is_accepted(tmp_path: Path) -> None:
    out = tmp_path / "out"
    out.mkdir()
    assert temp_env(_profile(out, out / "a" / "b")) == {TEMP_ENV: str(out / "a" / "b")}


def test_an_entry_whose_own_parent_is_a_link_is_accepted(tmp_path: Path) -> None:
    """macOS's `/var` is a link to `/private/var`, and a home folder may be a link: the entry's
    own parents are never checked."""
    real = tmp_path / "real"
    (real / "out" / "tmp").mkdir(parents=True)
    link = tmp_path / "link"
    link.symlink_to(real, target_is_directory=True)
    out = link / "out"
    assert temp_env(_profile(out, out / "tmp")) == {TEMP_ENV: str(out / "tmp")}


def test_the_sub_directory_is_matched_against_any_allow_entry(tmp_path: Path) -> None:
    first, second = tmp_path / "first", tmp_path / "second"
    (second / "tmp").mkdir(parents=True)
    first.mkdir()
    profile = dataclasses.replace(_profile(first, second / "tmp"), allow_write=(first, second))
    assert temp_env(profile) == {TEMP_ENV: str(second / "tmp")}


# ------------------------------------------------------------------ what temp_env refuses


def test_a_relative_temp_dir_is_refused(tmp_path: Path) -> None:
    _refused(_profile(tmp_path, Path("out/tmp")))


def test_a_relative_temp_dir_equal_to_a_relative_entry_is_refused() -> None:
    _refused(_profile(Path("out"), Path("out")))


def test_a_temp_dir_outside_every_allow_entry_is_refused(tmp_path: Path) -> None:
    out = tmp_path / "out"
    out.mkdir()
    _refused(_profile(out, tmp_path / "elsewhere"))


def test_a_temp_dir_that_is_not_normalised_is_refused(tmp_path: Path) -> None:
    """`allow/../elsewhere` is lexically inside `allow`; srt would make `elsewhere` writable."""
    out = tmp_path / "out"
    out.mkdir()
    _refused(_profile(out, out / ".." / "elsewhere"))
    _refused(_profile(out, out / "tmp" / ".."))


def test_a_sub_directory_of_a_deny_write_entry_is_refused(tmp_path: Path) -> None:
    out = tmp_path / "out"
    (out / "protected" / "tmp").mkdir(parents=True)
    _refused(_profile(out, out / "protected" / "tmp", deny_write=(out / "protected",)))
    _refused(_profile(out, out / "protected", deny_write=(out / "protected",)))


def test_a_path_inside_a_deny_read_entry_is_refused(tmp_path: Path) -> None:
    out = tmp_path / "out"
    (out / "secret" / "tmp").mkdir(parents=True)
    _refused(_profile(out, out / "secret" / "tmp", deny_read=(out / "secret",)))


@pytest.mark.parametrize("rel", [".env", ".env.local/tmp", "sub/.envrc/tmp/x"])
def test_a_path_matching_a_deny_write_pattern_is_refused(tmp_path: Path, rel: str) -> None:
    out = tmp_path / "out"
    out.mkdir()
    pattern = f"{out}/**/.env*"
    _refused(_profile(out, out / rel, deny_write_patterns=(pattern,)))


def test_a_path_not_matching_the_deny_write_patterns_is_accepted(tmp_path: Path) -> None:
    out = tmp_path / "out"
    out.mkdir()
    profile = _profile(out, out / "tmp", deny_write_patterns=(f"{out}/**/.env*",))
    assert temp_env(profile) == {TEMP_ENV: str(out / "tmp")}


def test_a_path_through_a_link_below_the_entry_is_refused(tmp_path: Path) -> None:
    """srt would resolve the link and make its target writable."""
    out = tmp_path / "out"
    out.mkdir()
    elsewhere = tmp_path / "elsewhere"
    elsewhere.mkdir()
    (out / "tmp").symlink_to(elsewhere, target_is_directory=True)
    _refused(_profile(out, out / "tmp"))
    _refused(_profile(out, out / "tmp" / "deeper"))


def test_a_link_below_the_entry_that_stays_inside_it_is_still_refused(tmp_path: Path) -> None:
    out = tmp_path / "out"
    (out / "real").mkdir(parents=True)
    (out / "tmp").symlink_to(out / "real", target_is_directory=True)
    _refused(_profile(out, out / "tmp"))


def test_a_link_loop_below_the_entry_is_refused(tmp_path: Path) -> None:
    """`os.path.realpath` returns a looping path as given, so the realpath comparison alone
    would pass it; repointing one link later would lead outside (security review)."""
    out = tmp_path / "out"
    out.mkdir()
    (out / "a").symlink_to(out / "b")
    (out / "b").symlink_to(out / "a")
    _refused(_profile(out, out / "a"))
    _refused(_profile(out, out / "a" / "tmp"))


def test_a_file_where_a_directory_is_expected_is_refused(tmp_path: Path) -> None:
    out = tmp_path / "out"
    out.mkdir()
    (out / "file").write_text("x", encoding="utf-8")
    _refused(_profile(out, out / "file" / "tmp"))


def test_a_deny_entry_spelled_through_a_link_still_covers_the_temp_dir(tmp_path: Path) -> None:
    """A deny entry named through another spelling of the same folder (macOS's `/var` and
    `/private/var`, a home folder that is a link) is compared after resolving links."""
    real = tmp_path / "real"
    (real / "out" / "secret" / "tmp").mkdir(parents=True)
    link = tmp_path / "link"
    link.symlink_to(real, target_is_directory=True)
    out = real / "out"
    _refused(_profile(out, out / "secret" / "tmp", deny_write=(link / "out" / "secret",)))
    _refused(_profile(out, out / "secret" / "tmp", deny_read=(link / "out",)))


def test_a_deny_entry_in_another_case_still_covers_the_temp_dir(tmp_path: Path) -> None:
    """macOS's disk ignores case, and `realpath` keeps the case as typed."""
    out = tmp_path / "out"
    (out / "secret" / "tmp").mkdir(parents=True)
    _refused(_profile(out, out / "secret" / "tmp", deny_write=(out / "SECRET",)))


def test_the_settings_dir_fallback_follows_the_same_rule(tmp_path: Path) -> None:
    out = tmp_path / "out"
    (out / "tmp").mkdir(parents=True)
    profile = dataclasses.replace(_profile(out, out), temp_dir=None, settings_dir=out / "tmp")
    assert temp_env(profile) == {TEMP_ENV: str(out / "tmp")}
    _refused(dataclasses.replace(profile, settings_dir=tmp_path / "elsewhere"))


def test_an_exact_entry_is_accepted_as_before_even_under_a_denied_path(tmp_path: Path) -> None:
    """The exact-match case is unchanged, so agents, gates and prepare behave as before."""
    out = tmp_path / "out"
    out.mkdir()
    profile = _profile(out, out, deny_write=(tmp_path,), deny_read=(tmp_path,))
    assert temp_env(profile) == {TEMP_ENV: str(out)}


# ------------------------------------------------------------------ profile_for


def _paths(tmp_path: Path, **extra: object) -> ProfilePaths:
    work, temp = tmp_path / "work", tmp_path / "temp"
    work.mkdir(exist_ok=True)
    temp.mkdir(exist_ok=True)
    return ProfilePaths(workspace=work, temp_dir=temp, home=tmp_path / "home", **extra)  # type: ignore[arg-type]


def test_a_scanner_profile_uses_its_temp_dir_inside_the_output_dir(tmp_path: Path) -> None:
    out = tmp_path / "out"
    (out / "tmp").mkdir(parents=True)
    paths = ProfilePaths(workspace=tmp_path, temp_dir=out / "tmp", home=tmp_path / "home",
                         output_dir=out)  # fmt: skip
    profile = profile_for(ProcessKind.SCANNER, NONE, paths, runtime="/bin/srt")
    assert profile.temp_dir == out / "tmp"
    assert profile.allow_write == (out,)
    assert temp_env(profile) == {TEMP_ENV: str(out / "tmp")}


def test_a_scanner_temp_dir_outside_the_output_dir_falls_back_to_it(tmp_path: Path) -> None:
    """`profile_for` never builds a scanner profile whose temp dir `temp_env` would refuse."""
    out = tmp_path / "out"
    out.mkdir()
    profile = profile_for(
        ProcessKind.SCANNER, NONE, _paths(tmp_path, output_dir=out), runtime="/bin/srt"
    )
    assert profile.temp_dir == out
    assert profile.allow_write == (out,)


def test_a_scanner_temp_dir_beside_the_output_dir_with_a_shared_prefix_falls_back(
    tmp_path: Path,
) -> None:
    out = tmp_path / "out"
    out.mkdir()
    paths = ProfilePaths(workspace=tmp_path, temp_dir=tmp_path / "out-tmp",
                         home=tmp_path / "home", output_dir=out)  # fmt: skip
    profile = profile_for(ProcessKind.SCANNER, NONE, paths, runtime="/bin/srt")
    assert profile.temp_dir == out


def test_the_other_kinds_are_unchanged(tmp_path: Path) -> None:
    paths = _paths(tmp_path, output_dir=tmp_path / "out", package_cache=tmp_path / "cache")
    for kind in (ProcessKind.AGENT, ProcessKind.GATE, ProcessKind.PREPARE):
        profile = profile_for(kind, NONE, paths, runtime="/bin/srt")
        assert profile.temp_dir == paths.temp_dir, kind
        assert profile.settings_dir == paths.temp_dir, kind
        assert profile.allow_write[:2] == (paths.workspace, paths.temp_dir), kind
        assert temp_env(profile) == {TEMP_ENV: str(paths.temp_dir)}, kind


# ------------------------------------------------------------------ run_tool


def test_run_tool_gives_the_scanner_profile_its_own_tmp(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    seen: dict[str, object] = {}

    def fake_run_safe(argv: list[str], **kwargs: object) -> ProcessResult:
        seen.update(kwargs)
        return ProcessResult(tuple(argv), 0, b"", b"", timed_out=False, truncated=False,
                             duration_s=0.0)  # fmt: skip

    monkeypatch.setattr(base, "run_safe", fake_run_safe)
    out = tmp_path / "out"
    ctx = ScanContext(repo=tmp_path, temp_dir=tmp_path, runtime="/bin/srt")
    run_tool(Tool("scanner", "install it"), "/bin/true", [], ctx, cwd=tmp_path, out_dir=out)
    profile = seen["sandbox"]
    assert isinstance(profile, SandboxProfile)
    assert profile.temp_dir == out / "tmp"
    assert profile.settings_dir == out / "tmp"
    assert profile.allow_write == (out,)
    env = seen["env"]
    assert isinstance(env, dict)
    assert env["TMPDIR"] == str(out / "tmp")  # pyright: ignore[reportUnknownMemberType]
    assert temp_env(profile) == {TEMP_ENV: str(out / "tmp")}
    assert (out / "tmp").stat().st_mode & 0o777 == 0o700
