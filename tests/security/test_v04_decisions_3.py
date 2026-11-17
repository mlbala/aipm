"""The owner's v0.4 decisions, session 3 (docs/security/reviews/v0.4-decisions-progress.md):
the nightly `ci-long` workflow (v0.3 rec 6), the real `srt` in CI (v0.3 rec 3), `install.sh`
installing the attested wheel (N-7), and pnpm's flags for the run's store (the medium the real
`srt` showed).

The workflows are read with the safe YAML loader and checked as written; nothing here runs on
GitHub. `tests/security/test_release_supply_chain.py` checks every workflow's triggers,
permissions and action pins; the tests here check what each new job is for.
"""

import dataclasses
import json
import re
import shlex
from pathlib import Path
from typing import Any

import pytest

from aipm.config.schema import Config
from aipm.domain.models import GateStatus
from aipm.execution.package_cache import cache_args
from aipm.gates.command_gate import run_command_gate, run_prepare
from aipm.gates.context import GateContext
from tests.conftest import REPO_ROOT
from tests.integration.test_install_sh import (
    SCRIPT,
    WHEEL,
    WHEEL_BYTES,
    recording_uv,
    release,
    run,
    script_trusting,
    serve,
    sha256,
    stub,
    without_gh,
)
from tests.integration.test_install_sh import env as env  # noqa: PLC0414 - the fixture
from tests.security.test_gates import make_ctx
from tests.security.test_release_supply_chain import (
    README,
    WORKFLOWS,
    ci_uv_version,
    load,
    steps,
)

CI_LONG = WORKFLOWS / "ci-long.yml"


def runs(job: dict[str, Any]) -> list[str]:
    return [str(s["run"]).replace("\\\n", " ") for s in steps(job) if "run" in s]


def uses(job: dict[str, Any], action: str) -> dict[str, Any]:
    found = [s for s in steps(job) if str(s.get("uses", "")).startswith(f"{action}@")]
    assert len(found) == 1, action
    return found[0]


# ------------------------------------------------------------------ v0.3 rec 6: ci-long


def test_ci_long_runs_nightly_and_by_hand_only() -> None:
    """v0.3 rec 6 (open since v0.1; RT03-10 was found only by ci-long): the long fuzzing run
    is too slow for every push, so it runs once a night and on demand, never on a PR."""
    triggers = load(CI_LONG)["on"]
    assert set(triggers) == {"schedule", "workflow_dispatch"}
    crons = [entry["cron"] for entry in triggers["schedule"]]
    assert len(crons) == 1
    minute, hour, day, month, weekday = crons[0].split()
    assert minute.isdigit() and hour.isdigit()
    assert (day, month, weekday) == ("*", "*", "*")  # every night


def test_ci_long_runs_the_long_profile_over_the_properties_and_security_suite() -> None:
    jobs = load(CI_LONG)["jobs"]
    assert len(jobs) == 1
    job = next(iter(jobs.values()))
    assert job["permissions"] == {"contents": "read"}
    assert 0 < int(job["timeout-minutes"]) <= 180
    assert str(uses(job, "astral-sh/setup-uv")["with"]["version"]) == ci_uv_version()
    commands = [shlex.split(r) for r in runs(job)]
    assert ["uv", "sync", "--frozen", "--all-extras"] in commands
    assert [
        "uv", "run", "--frozen", "pytest", "--hypothesis-profile=ci-long",
        "tests/property", "tests/security",
    ] in commands  # fmt: skip


def test_the_ci_long_profile_runs_at_least_2000_examples() -> None:
    text = (REPO_ROOT / "tests" / "conftest.py").read_text(encoding="utf-8")
    assert 'settings.register_profile("ci-long", max_examples=2000, deadline=None)' in text


# ------------------------------------------------------------------ v0.3 rec 3: the real srt

SANDBOX_DIR = REPO_ROOT / ".github" / "sandbox"
EXACT_VERSION = re.compile(r"\d+\.\d+\.\d+")


def sandbox_job() -> dict[str, Any]:
    return dict(load(WORKFLOWS / "ci.yml")["jobs"]["sandbox"])


def test_the_sandbox_job_runs_on_ubuntu_and_macos_with_read_only_permissions() -> None:
    job = sandbox_job()
    assert job["permissions"] == {"contents": "read"}
    assert job["strategy"]["matrix"]["os"] == ["ubuntu-latest", "macos-latest"]
    assert job["runs-on"] == "${{ matrix.os }}"
    assert 0 < int(job["timeout-minutes"]) <= 60


def test_the_sandbox_job_installs_the_locked_packages_without_scripts() -> None:
    """v0.3 rec 3, the owner's conditions: srt at an exact version, the lockfile committed,
    `npm ci --ignore-scripts`. Nothing else in any workflow installs from npm."""
    job = sandbox_job()
    node = uses(job, "actions/setup-node")
    assert node["with"]["package-manager-cache"] is False  # no cache to poison
    assert EXACT_VERSION.fullmatch(str(node["with"]["node-version"]))
    installs = [s for s in steps(job) if "npm" in str(s.get("run", ""))]
    assert len(installs) == 1
    assert shlex.split(str(installs[0]["run"])) == [
        "npm", "ci", "--ignore-scripts", "--no-audit", "--no-fund",
    ]  # fmt: skip
    assert installs[0]["working-directory"] == ".github/sandbox"
    for path in WORKFLOWS.glob("*.y*ml"):
        for other in load(path)["jobs"].values():
            for command in runs(other):
                words = command.split()
                if {"npm", "npx", "pnpm", "yarn"} & set(words):
                    assert command == "npm ci --ignore-scripts --no-audit --no-fund", command


def test_the_sandbox_packages_are_pinned_exactly_and_run_no_install_scripts() -> None:
    manifest = json.loads((SANDBOX_DIR / "package.json").read_text(encoding="utf-8"))
    lock = json.loads((SANDBOX_DIR / "package-lock.json").read_text(encoding="utf-8"))
    wanted = manifest["dependencies"]
    assert set(wanted) == {"@anthropic-ai/sandbox-runtime", "pnpm"}
    assert all(EXACT_VERSION.fullmatch(v) for v in wanted.values()), wanted
    assert lock["lockfileVersion"] == 3
    packages = lock["packages"]
    assert packages[""]["dependencies"] == wanted
    for name, version in wanted.items():
        assert packages[f"node_modules/{name}"]["version"] == version
    for path, entry in packages.items():
        if not path:
            continue
        assert "hasInstallScript" not in entry, path
        assert str(entry["integrity"]).startswith("sha512-"), path
        assert str(entry["resolved"]).startswith("https://registry.npmjs.org/"), path


def test_the_sandbox_job_sets_up_linux_only_on_linux_and_requires_every_tool() -> None:
    """On Ubuntu, bubblewrap needs unprivileged user namespaces, which AppArmor restricts by
    default; the sysctl runs only there. Every real-sandbox test must run: a missing srt,
    Go, Cargo or pnpm fails the job instead of skipping."""
    job = sandbox_job()
    linux = [s for s in steps(job) if "sysctl" in str(s.get("run", ""))]
    assert len(linux) == 1
    assert linux[0]["if"] == "runner.os == 'Linux'"
    assert "kernel.apparmor_restrict_unprivileged_userns=0" in str(linux[0]["run"])
    for package in ("bubblewrap", "socat", "ripgrep"):
        assert package in str(linux[0]["run"])
    tests = [s for s in steps(job) if "pytest" in str(s.get("run", ""))]
    assert len(tests) == 1
    assert tests[0]["env"] == {"AIPM_REQUIRE_REAL_SRT": "1"}
    assert "tests/security/test_real_sandbox.py" in str(tests[0]["run"])


# ------------------------------------------------------------------ N-7: install.sh


def gh_stub(env: dict[str, str], tmp_path: Path, *, logged_in: bool, verified: bool) -> Path:
    """A `gh` first on PATH that logs each call; `auth status` and `attestation verify` succeed
    or fail as asked."""
    log = tmp_path / "gh.log"
    body = (
        f'printf "%s\\n" "$*" >> "{log}"\n'
        f'case "$1 $2" in "auth status") exit {0 if logged_in else 1} ;;\n'
        f'"attestation verify") exit {0 if verified else 1} ;; esac\nexit 3'
    )
    stub(Path(env["PATH"].split(":")[0]) / "gh", body)
    return log


def readme_verify_flags() -> list[str]:
    """The README's `gh attestation verify` options, without the file and with the tag left
    out of `--source-ref`."""
    for line in README.read_text(encoding="utf-8").splitlines():
        if line.strip().startswith("gh attestation verify"):
            words = shlex.split(line.split("#", 1)[0])[4:]  # after "gh attestation verify FILE"
            return [re.sub(r"^refs/tags/.*", "refs/tags/", w) for w in words]
    raise AssertionError("no gh attestation verify in the README")


@pytest.mark.parametrize("tag", ["v0.3.9", "v0.1.0", "v0.0.99", "v0.4.0-rc1"])
def test_install_sh_refuses_a_tag_older_than_v0_4_0(
    env: dict[str, str], tmp_path: Path, tag: str
) -> None:
    """N-7: releases before v0.4.0 publish no attested wheel. The script refuses them before any
    download, and prints the command that builds the tag from source instead."""
    env = without_gh(env, tmp_path)
    uv_log = recording_uv(env, tmp_path)
    curl_log = serve(env, tmp_path, release(tag))
    code, _, err = run(env, "-t", tag, cwd=tmp_path)
    assert code == 2, err
    assert f"uv tool install git+https://github.com/mlbala/aipm@{tag}" in err
    assert not curl_log.exists()
    assert not uv_log.exists()


@pytest.mark.parametrize("tag", ["v0.4.0", "v0.4.1", "v0.10.0", "v1.0.0", "v0.5.0-rc1"])
def test_install_sh_installs_v0_4_0_and_later(
    env: dict[str, str], tmp_path: Path, tag: str
) -> None:
    env = without_gh(env, tmp_path)
    uv_log = recording_uv(env, tmp_path)
    serve(env, tmp_path, release(tag))
    code, _, err = run(env, "-t", tag, cwd=tmp_path)
    assert code == 0, err
    assert uv_log.read_text(encoding="utf-8").endswith(WHEEL_BYTES.decode())


def test_install_sh_pins_the_uv_installer_by_hash() -> None:
    text = SCRIPT.read_text(encoding="utf-8")
    pins = re.findall(r'^UV_INSTALLER_SHA256="([0-9a-f]{64})"$', text, flags=re.MULTILINE)
    assert len(pins) == 1
    assert pins[0] != sha256(b"")
    assert set(pins[0]) != {"0"}  # not a placeholder


def test_install_sh_never_runs_a_uv_installer_with_another_hash(
    env: dict[str, str], tmp_path: Path
) -> None:
    """N-7 (RT04-19's remainder): the pinned release URL alone trusted whatever GitHub served
    for it. An installer whose SHA-256 differs from the pinned one is never run."""
    env = without_gh(env, tmp_path)
    ran = tmp_path / "ran.log"
    served = f'echo ran >> "{ran}"\n'.encode()
    url = "https://github.com/astral-sh/uv/releases/download/0.13.6/uv-installer.sh"
    serve(env, tmp_path, {url: served, **release("v0.4.0")})
    script = script_trusting(tmp_path, b"the installer the owner pinned\n")
    code, _, err = run(env, "-y", "-t", "v0.4.0", cwd=tmp_path, script=script)
    assert code == 1, err
    assert "SHA-256" in err
    assert not ran.exists()


def test_install_sh_installs_nothing_on_a_wheel_hash_mismatch(
    env: dict[str, str], tmp_path: Path
) -> None:
    env = without_gh(env, tmp_path)
    uv_log = recording_uv(env, tmp_path)
    files = release("v0.4.1", sums=f"{sha256(b'another wheel')}  {WHEEL}\n")
    serve(env, tmp_path, files)
    code, _, err = run(env, "-t", "v0.4.1", cwd=tmp_path)
    assert code == 1, err
    assert "does not match" in err
    assert not uv_log.exists()


@pytest.mark.parametrize(
    "sums",
    [
        "",
        f"{'0' * 64}  aipm-0.4.1.tar.gz\n",
        f"{sha256(WHEEL_BYTES)}  {WHEEL}\n{sha256(WHEEL_BYTES)}  aipm-9.9.9-py3-none-any.whl\n",
        f"{sha256(WHEEL_BYTES)}  ../{WHEEL}\n",
        f"{sha256(WHEEL_BYTES)} *{WHEEL}\n",
    ],
    ids=["empty", "no-wheel", "two-wheels", "a-path", "binary-mode"],
)
def test_install_sh_installs_nothing_when_sha256sums_lists_no_single_wheel(
    env: dict[str, str], tmp_path: Path, sums: str
) -> None:
    """N-7: the wheel's name comes from SHA256SUMS (a pre-release's wheel is named by its
    normalised version), so exactly one plain wheel name must be listed."""
    env = without_gh(env, tmp_path)
    uv_log = recording_uv(env, tmp_path)
    serve(env, tmp_path, release("v0.4.1", sums=sums))
    code, _, err = run(env, "-t", "v0.4.1", cwd=tmp_path)
    assert code == 1, err
    assert "SHA256SUMS" in err
    assert not uv_log.exists()


@pytest.mark.parametrize("missing", ["SHA256SUMS", WHEEL])
def test_install_sh_installs_nothing_when_a_download_fails(
    env: dict[str, str], tmp_path: Path, missing: str
) -> None:
    env = without_gh(env, tmp_path)
    uv_log = recording_uv(env, tmp_path)
    files = {k: v for k, v in release("v0.4.1").items() if not k.endswith(f"/{missing}")}
    serve(env, tmp_path, files)
    code, _, _ = run(env, "-t", "v0.4.1", cwd=tmp_path)
    assert code != 0
    assert not uv_log.exists()


def test_install_sh_verifies_the_attestation_with_the_readme_flags(
    env: dict[str, str], tmp_path: Path
) -> None:
    """N-7 (a): with gh installed, the wheel is installed only after `gh attestation verify`
    accepts it, with the same pinned signer workflow and tag the README tells users to check."""
    uv_log = recording_uv(env, tmp_path)
    gh_log = gh_stub(env, tmp_path, logged_in=True, verified=True)
    serve(env, tmp_path, release("v0.4.1"))
    code, out, err = run(env, "-t", "v0.4.1", cwd=tmp_path)
    assert code == 0, err
    auth, verify = gh_log.read_text(encoding="utf-8").splitlines()
    assert auth.split()[:2] == ["auth", "status"]
    words = verify.split()
    assert words[:2] == ["attestation", "verify"]
    assert uv_log.read_text(encoding="utf-8").split()[2] == words[2]  # the file it checked
    assert words[3:] == [
        "--repo", "mlbala/aipm",
        "--signer-workflow", "mlbala/aipm/.github/workflows/release.yml",
        "--source-ref", "refs/tags/v0.4.1",
        "--deny-self-hosted-runners",
    ]  # fmt: skip
    assert [re.sub(r"^refs/tags/.*", "refs/tags/", w) for w in words[3:]] == (readme_verify_flags())
    assert "only the SHA-256" not in out


def test_install_sh_installs_nothing_when_the_attestation_fails(
    env: dict[str, str], tmp_path: Path
) -> None:
    uv_log = recording_uv(env, tmp_path)
    gh_stub(env, tmp_path, logged_in=True, verified=False)
    serve(env, tmp_path, release("v0.4.1"))
    code, _, err = run(env, "-t", "v0.4.1", cwd=tmp_path)
    assert code == 1, err
    assert "verification failed" in err
    assert "gh auth login" not in err
    assert not uv_log.exists()


def test_install_sh_tells_a_logged_out_gh_from_a_failed_verification(
    env: dict[str, str], tmp_path: Path
) -> None:
    """The owner's choice for N-7: fail closed (exit 1) when gh cannot check, and say why."""
    uv_log = recording_uv(env, tmp_path)
    gh_log = gh_stub(env, tmp_path, logged_in=False, verified=True)
    serve(env, tmp_path, release("v0.4.1"))
    code, _, err = run(env, "-t", "v0.4.1", cwd=tmp_path)
    assert code == 1, err
    assert "not logged in" in err
    assert "run gh auth login and retry" in err
    assert "verification failed" not in err
    assert "attestation" not in gh_log.read_text(encoding="utf-8")
    assert not uv_log.exists()


def test_install_sh_without_gh_says_only_the_hash_was_checked(
    env: dict[str, str], tmp_path: Path
) -> None:
    env = without_gh(env, tmp_path)
    recording_uv(env, tmp_path)
    serve(env, tmp_path, release("v0.4.1"))
    code, out, err = run(env, "-t", "v0.4.1", cwd=tmp_path)
    assert code == 0, err
    assert "only the SHA-256 was checked" in out + err


def test_install_sh_never_builds_from_source() -> None:
    """N-7: the tag install built from source with a build backend resolved at install time
    (R-21). The only `git+` left is in the message for tags older than v0.4.0."""
    text = SCRIPT.read_text(encoding="utf-8")
    installs = [line.strip() for line in text.splitlines() if "tool install" in line]
    runs_uv = [line for line in installs if line.startswith('"$UV"')]
    assert runs_uv == ['"$UV" tool install "$dir/$wheel"']
    assert all("git+" not in line for line in runs_uv)
    assert text.count("git+") == 1


@pytest.mark.parametrize(
    "tag", ["junk\nv0.4.0", "v0.1.0\nrm -rf ~", "v0.4.0\x1b[2J", "v0.4.0 ", "v0.4.0/../x"]
)
def test_install_sh_refuses_a_tag_with_other_characters(
    env: dict[str, str], tmp_path: Path, tag: str
) -> None:
    """Security review of session 3 (low): grep checks each line on its own, so a tag with a
    second line passed when one line matched, and the refusal for old tags printed the other
    line as part of the command to run. A tag is now refused for any character outside
    letters, digits, `.` and `-`, before anything else reads it."""
    env = without_gh(env, tmp_path)
    uv_log = recording_uv(env, tmp_path)
    curl_log = serve(env, tmp_path, release("v0.4.0"))
    code, out, err = run(env, "-t", tag, cwd=tmp_path)
    assert code == 2, err
    assert "\x1b" not in out + err
    assert "rm -rf" not in out + err
    assert "uv tool install git+" not in err
    assert not curl_log.exists()
    assert not uv_log.exists()


# ------------------------------------------------------------------ pnpm and the run's store

ARGV_RECORDER = '#!/bin/sh\nprintf "%s\\n" "$@" > "{log}"\n'


def pnpm_ctx(tmp_path: Path, program: str, *, gate_run: tuple[str, ...] = ()) -> GateContext:
    """A gate context whose prepare is `<program> install --frozen-lockfile`, with its own run
    cache, and one gate `unit` when `gate_run` is given."""
    ctx = make_ctx(tmp_path)
    cfg = Config.model_validate(
        {
            "allowed_executables": [[program, "install"], [program, "test"]],
            "prepare": {"run": [program, "install", "--frozen-lockfile"]},
            "gates": {"unit": {"run": list(gate_run)}} if gate_run else {},
        }
    )
    return dataclasses.replace(ctx, cfg=cfg, package_cache=tmp_path / "run-cache")


def recording_pnpm(tmp_path: Path) -> tuple[str, Path]:
    log = tmp_path / "argv.log"
    bin_dir = tmp_path / "pnpm-bin"
    bin_dir.mkdir()
    program = bin_dir / "pnpm"
    program.write_text(ARGV_RECORDER.format(log=log), encoding="utf-8")
    program.chmod(0o755)
    return str(program), log


def test_pnpm_gets_the_run_store_and_copying_as_flags(tmp_path: Path) -> None:
    """Session 3 (the owner's fix): pnpm 10 lets a committed `pnpm-workspace.yaml` override
    the environment, but not its own flags. `copy`, not `clone-or-copy`: pnpm 10.34.9 dropped a
    `clone-or-copy` flag that repeated the environment's value, and the file's `hardlink` won."""
    cache = tmp_path / "cache"
    assert cache_args("/opt/bin/pnpm", cache) == (
        f"--store-dir={cache / 'pnpm-store'}",
        "--package-import-method=copy",
    )
    for other in ("npm", "uv", "go", "cargo", "/usr/bin/python3", "pnpx"):
        assert cache_args(other, cache) == ()


def test_prepare_puts_the_pnpm_flags_before_the_subcommand(tmp_path: Path) -> None:
    """Before the subcommand they are pnpm's own options whatever the trusted prepare argv
    runs; the argv the command policy checked is otherwise unchanged."""
    program, log = recording_pnpm(tmp_path)
    ctx = pnpm_ctx(tmp_path, program)
    outcome = run_prepare(ctx)
    assert outcome is not None and outcome.result.status is GateStatus.PASS, outcome
    assert log.read_text(encoding="utf-8").splitlines() == [
        f"--store-dir={ctx.package_dir / 'pnpm-store'}",
        "--package-import-method=copy",
        "install",
        "--frozen-lockfile",
    ]


def test_gates_running_pnpm_get_no_extra_flags(tmp_path: Path) -> None:
    """A gate's `pnpm test` (or `pnpm run x`) would pass flags after the script name to the
    script; gates install nothing, so they keep their argv."""
    program, log = recording_pnpm(tmp_path)
    ctx = pnpm_ctx(tmp_path, program, gate_run=(program, "test"))
    outcome = run_command_gate("unit", ctx.cfg.gates["unit"], ctx, paths=[], required=True)
    assert outcome.result.status is GateStatus.PASS, outcome.result.summary
    assert log.read_text(encoding="utf-8").splitlines() == ["test"]
