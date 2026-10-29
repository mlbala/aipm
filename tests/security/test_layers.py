"""The import-linter contracts hold, and they really catch violations (ARCHITECTURE §5.1).

The violation tests copy the package to a temporary directory, add one offending module, and
check that `lint-imports` fails on the right contract. The L0 cases also prove that
standard-library modules such as `subprocess` and `socket` are tracked.
"""

import os
import re
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

from tests.conftest import REPO_ROOT

LINT_IMPORTS = Path(sys.executable).with_name("lint-imports")
BROKEN = re.compile(r" BROKEN(?: \(\d+ ignored imports?\))?$")


def lint_imports(cwd: Path, *, pythonpath: Path | None = None) -> subprocess.CompletedProcess[str]:
    env = dict(os.environ)
    if pythonpath is not None:
        env["PYTHONPATH"] = str(pythonpath)
    return subprocess.run(
        [str(LINT_IMPORTS), "--no-cache"],
        cwd=cwd,
        env=env,
        capture_output=True,
        text=True,
        check=False,
        timeout=120,
    )


def test_contracts_hold_on_the_package() -> None:
    proc = lint_imports(REPO_ROOT)
    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert "0 broken" in proc.stdout


@pytest.mark.parametrize(
    ("package", "source", "contract"),
    [
        ("domain", "import subprocess\n", "L0 is pure"),
        ("security", "import socket\n", "L0 is pure"),
        ("domain", "import aipm.cli.main\n", "Layers"),
        ("roles", "import aipm.gates.runner\n", "Layers"),
        ("gates", "import aipm.adapters.base\n", "Layers"),
        ("cli", "import aipm.state.store\n", "cli imports only"),
        ("app", "import anthropic\n", "Only aipm.llm.providers imports the LLM SDKs"),
        ("state", "import subprocess\n", "Only aipm.execution.process imports subprocess"),
        # New modules are covered by default (step 01 security review, finding 7).
        ("execution", "import subprocess\n", "Only aipm.execution.process imports subprocess"),
        ("llm", "import anthropic\n", "Only aipm.llm.providers imports the LLM SDKs"),
        ("state", "import socket\n", "Only aipm.llm and aipm.scanners.registry import network"),
        ("scanners", "import urllib.request\n", "Only aipm.llm and aipm.scanners.registry"),
        ("app", "import http.client\n", "Only aipm.llm and aipm.scanners.registry"),
        ("gates", "import ssl\n", "Only aipm.llm and aipm.scanners.registry"),
    ],
)
def test_violation_is_caught(tmp_path: Path, package: str, source: str, contract: str) -> None:
    src = tmp_path / "src"
    shutil.copytree(
        REPO_ROOT / "src" / "aipm", src / "aipm", ignore=shutil.ignore_patterns("__pycache__")
    )
    (src / "aipm" / package / "_violation.py").write_text(source, encoding="utf-8")
    shutil.copy(REPO_ROOT / "pyproject.toml", tmp_path / "pyproject.toml")

    proc = lint_imports(tmp_path, pythonpath=src)

    assert proc.returncode != 0, proc.stdout
    # A contract with ignore_imports reports "BROKEN (1 ignored import)".
    broken = [line for line in proc.stdout.splitlines() if BROKEN.search(line)]
    assert any(line.startswith(contract) for line in broken), proc.stdout
    assert f"aipm.{package}._violation" in proc.stdout


def copy_with(tmp_path: Path, package: str, source: str) -> Path:
    src = tmp_path / "src"
    shutil.copytree(
        REPO_ROOT / "src" / "aipm", src / "aipm", ignore=shutil.ignore_patterns("__pycache__")
    )
    (src / "aipm" / package / "_allowed.py").write_text(source, encoding="utf-8")
    shutil.copy(REPO_ROOT / "pyproject.toml", tmp_path / "pyproject.toml")
    return src


def test_the_llm_package_may_use_the_network(tmp_path: Path) -> None:
    src = copy_with(tmp_path, "llm", "import httpx\nimport socket\n")
    proc = lint_imports(tmp_path, pythonpath=src)
    assert proc.returncode == 0, proc.stdout
