"""`install.sh` (build prompt 06, item 9): POSIX sh, at most 80 lines, `set -eu`; prints what it
will do first; installs uv only after asking (or with `-y`); then `uv tool install` of the tag.

The tests run it with stub `uv` and `curl` on a minimal PATH, without a terminal.
"""

from pathlib import Path

import pytest

from tests.conftest import REPO_ROOT, run_program

SCRIPT = REPO_ROOT / "install.sh"


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


def run(env: dict[str, str], *args: str, cwd: Path) -> tuple[int, str, str]:
    result = run_program(["sh", str(SCRIPT), *args], env=env, cwd=cwd)
    return result.returncode, result.stdout, result.stderr


def test_the_script_is_small_posix_and_strict(tmp_path: Path) -> None:
    text = SCRIPT.read_text(encoding="utf-8")
    assert text.startswith("#!/bin/sh\n")
    assert "\nset -eu\n" in text
    assert len(text.splitlines()) <= 80
    assert run_program(["sh", "-n", str(SCRIPT)], env={"PATH": "/usr/bin:/bin"},
                       cwd=tmp_path).returncode == 0  # fmt: skip
    assert "| sh" not in text and "|sh" not in text


def test_with_uv_it_installs_the_tag(env: dict[str, str], tmp_path: Path) -> None:
    log = tmp_path / "uv.log"
    stub(Path(env["PATH"].split(":")[0]) / "uv", f'echo "$@" >> "{log}"')
    code, out, err = run(env, "-t", "v0.2.1", cwd=tmp_path)
    assert code == 0, err
    assert log.read_text(encoding="utf-8") == (
        "tool install git+https://github.com/mlbala/aipm@v0.2.1\n"
    )
    assert out.index("This will:") < out.index("Done.")
    assert "2. run: uv tool install git+https://github.com/mlbala/aipm@v0.2.1" in out


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
    curl_body = (
        'out=""; while [ $# -gt 0 ]; do [ "$1" = "-o" ] && out="$2"; shift; done\n'
        f"cat > \"$out\" <<'X'\n{installer}\nX"
    )
    stub(Path(env["PATH"].split(":")[0]) / "curl", curl_body)
    code, _, err = run(env, "-y", cwd=tmp_path)
    assert code == 0, err
    assert log.read_text(encoding="utf-8").startswith("tool install git+https://github.com/")


@pytest.mark.parametrize("args", [["-t", "v1; rm -rf /"], ["-t", "main"], ["-x"]])
def test_bad_arguments_exit_2(env: dict[str, str], tmp_path: Path, args: list[str]) -> None:
    code, _, _ = run(env, *args, cwd=tmp_path)
    assert code == 2
