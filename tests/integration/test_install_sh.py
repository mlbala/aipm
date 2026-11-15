"""`install.sh` (build prompt 06, item 9; red-team v0.4 decision N-7): POSIX sh, at most 120
lines, `set -eu`; prints what it will do first; installs uv only after asking (or with `-y`);
then installs the release's wheel, checked against its `SHA256SUMS` (and its attestation when gh
is installed), with `uv tool install`.

The tests run it with stub `uv`, `curl` and `gh` on a minimal PATH, without a terminal. The
stub `curl` serves a fake release by URL.
"""

import hashlib
import os
import re
from pathlib import Path

import pytest

from tests.conftest import REPO_ROOT, run_program

SCRIPT = REPO_ROOT / "install.sh"
RELEASES = "https://github.com/mlbala/aipm/releases/download"
WHEEL = "aipm-0.4.1-py3-none-any.whl"
WHEEL_BYTES = b"a fake wheel for the install.sh tests\n"


def stub(path: Path, body: str) -> Path:
    path.write_text(f"#!/bin/sh\n{body}\n", encoding="utf-8")
    path.chmod(0o755)
    return path


@pytest.fixture
def env(tmp_path: Path) -> dict[str, str]:
    for tool in ("uv", "curl"):
        if any((Path(d) / tool).exists() for d in ("/usr/bin", "/bin")) and tool == "uv":
            pytest.skip("uv is installed system-wide")
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    home = tmp_path / "home"
    home.mkdir()
    return {"PATH": f"{bin_dir}:/usr/bin:/bin", "HOME": str(home), "LANG": "C"}


def run(env: dict[str, str], *args: str, cwd: Path, script: Path = SCRIPT) -> tuple[int, str, str]:
    result = run_program(["sh", str(script), *args], env=env, cwd=cwd)
    return result.returncode, result.stdout, result.stderr


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def without_gh(env: dict[str, str], tmp_path: Path) -> dict[str, str]:
    """`env` with /usr/bin and /bin replaced by links to every program in them but gh and uv: a
    GitHub runner has its own /usr/bin/gh, which the script would otherwise find."""
    system = tmp_path / "system-bin"
    system.mkdir(exist_ok=True)
    for directory in ("/usr/bin", "/bin"):
        for entry in os.scandir(directory):
            link = system / entry.name
            if entry.name not in {"gh", "uv"} and not os.path.lexists(link):
                link.symlink_to(entry.path)
    return {**env, "PATH": f"{env['PATH'].split(':')[0]}:{system}"}


def release(
    tag: str = "v0.4.1", *, wheel: bytes = WHEEL_BYTES, sums: str | None = None
) -> dict[str, bytes]:
    """The files of a fake release, by URL: the wheel and `SHA256SUMS`."""
    if sums is None:
        sums = f"{sha256(wheel)}  {WHEEL}\n{'0' * 64}  aipm-0.4.1.tar.gz\n"
    return {f"{RELEASES}/{tag}/SHA256SUMS": sums.encode(), f"{RELEASES}/{tag}/{WHEEL}": wheel}


def serve(env: dict[str, str], tmp_path: Path, files: dict[str, bytes]) -> Path:
    """A `curl` that writes `files[url]` to its `-o` file, or exits 22 (as `curl -f` on an HTTP
    error) for any other URL. Returns its log of the URLs asked for."""
    root = tmp_path / "served"
    root.mkdir(exist_ok=True)
    log = tmp_path / "curl.log"
    cases: list[str] = []
    for number, (url, data) in enumerate(files.items()):
        (root / str(number)).write_bytes(data)
        cases.append(f"  '{url}') cat '{root / str(number)}' > \"$out\" ;;")
    body = (
        'out=""; url=""\n'
        'while [ $# -gt 0 ]; do case "$1" in -o) out="$2"; shift ;; https://*) url="$1" ;; esac; '
        "shift; done\n"
        f'echo "$url" >> "{log}"\n'
        'case "$url" in\n' + "\n".join(cases) + "\n  *) exit 22 ;;\nesac"
    )
    stub(Path(env["PATH"].split(":")[0]) / "curl", body)
    return log


def recording_uv(env: dict[str, str], tmp_path: Path) -> Path:
    """A `uv` that logs its arguments, then the content of the file it was asked to install."""
    log = tmp_path / "uv.log"
    stub(
        Path(env["PATH"].split(":")[0]) / "uv",
        f'echo "$@" >> "{log}"\nif [ -f "$3" ]; then cat "$3" >> "{log}"; fi',
    )
    return log


def script_trusting(tmp_path: Path, installer: bytes) -> Path:
    """A copy of install.sh that pins `installer`'s SHA-256 as uv's installer (N-7: the script
    has no test seam; the test edits its own copy)."""
    text, count = re.subn(
        r'^UV_INSTALLER_SHA256="[0-9a-f]{64}"$',
        f'UV_INSTALLER_SHA256="{sha256(installer)}"',
        SCRIPT.read_text(encoding="utf-8"),
        flags=re.MULTILINE,
    )
    assert count == 1
    copy = tmp_path / "install-copy.sh"
    copy.write_text(text, encoding="utf-8")
    return copy


def test_the_script_is_small_posix_and_strict(tmp_path: Path) -> None:
    text = SCRIPT.read_text(encoding="utf-8")
    assert text.startswith("#!/bin/sh\n")
    assert "\nset -eu\n" in text
    assert len(text.splitlines()) <= 120
    assert run_program(["sh", "-n", str(SCRIPT)], env={"PATH": "/usr/bin:/bin"},
                       cwd=tmp_path).returncode == 0  # fmt: skip
    assert "| sh" not in text and "|sh" not in text


def test_with_uv_it_installs_the_tag(env: dict[str, str], tmp_path: Path) -> None:
    env = without_gh(env, tmp_path)
    log = recording_uv(env, tmp_path)
    serve(env, tmp_path, release("v0.4.1"))
    code, out, err = run(env, "-t", "v0.4.1", cwd=tmp_path)
    assert code == 0, err
    command, *installed = log.read_text(encoding="utf-8").splitlines()
    assert re.fullmatch(rf"tool install /\S+/{re.escape(WHEEL)}", command), command
    assert installed == [WHEEL_BYTES.decode().strip()]
    assert out.index("This will:") < out.index("Done.")
    assert f"download the wheel and SHA256SUMS of v0.4.1 from {RELEASES}/v0.4.1/" in out


def test_without_uv_it_asks_and_a_missing_answer_installs_nothing(
    env: dict[str, str], tmp_path: Path
) -> None:
    curl_log = tmp_path / "curl.log"
    stub(Path(env["PATH"].split(":")[0]) / "curl", f'echo called >> "{curl_log}"')
    code, out, err = run(env, cwd=tmp_path)
    assert code == 1
    assert "install uv with its official installer" in out
    assert "not installing uv" in err
    assert not curl_log.exists()


def test_with_yes_it_installs_uv_then_aipm(env: dict[str, str], tmp_path: Path) -> None:
    log = tmp_path / "uv.log"
    home = Path(env["HOME"])
    installer = (
        f'mkdir -p "{home}/.local/bin"\n'
        f'printf \'#!/bin/sh\\necho "$@" >> "{log}"\\n\' > "{home}/.local/bin/uv"\n'
        f'chmod +x "{home}/.local/bin/uv"'
    )
    env = without_gh(env, tmp_path)
    url = "https://github.com/astral-sh/uv/releases/download/0.13.6/uv-installer.sh"
    serve(env, tmp_path, {url: installer.encode(), **release("v0.4.0")})
    code, _, err = run(
        env, "-y", cwd=tmp_path, script=script_trusting(tmp_path, installer.encode())
    )
    assert code == 0, err
    assert re.fullmatch(rf"tool install /\S+/{re.escape(WHEEL)}\n", log.read_text(encoding="utf-8"))


@pytest.mark.parametrize("args", [["-t", "v1; rm -rf /"], ["-t", "main"], ["-x"]])
def test_bad_arguments_exit_2(env: dict[str, str], tmp_path: Path, args: list[str]) -> None:
    code, _, _ = run(env, *args, cwd=tmp_path)
    assert code == 2
