"""The ruff banned-api rule stops every way to start a process outside execution/process.py.

ARCHITECTURE §5.1, SECURITY.md §10 rule 1, AGENTS.md rule 1. The banned list is read from
pyproject.toml, so an entry without a test case fails `test_every_banned_entry_has_a_case`.
"""

import ast
import json
import subprocess
import sys
import tomllib
from pathlib import Path

import pytest

from tests.conftest import REPO_ROOT

# Where the snippets pretend to live: inside the package, but not the exempt module.
CHECKED_PATH = "src/aipm/execution/_banned_api_probe.py"
EXEMPT_PATH = "src/aipm/execution/process.py"

# One snippet per banned entry; each must trigger TID251 for that entry.
CASES: dict[str, str] = {
    "subprocess": "import subprocess\n",
    "asyncio.subprocess": "from asyncio import subprocess\n",
    "asyncio.create_subprocess_exec": "import asyncio\nasyncio.create_subprocess_exec('x')\n",
    "asyncio.create_subprocess_shell": "import asyncio\nasyncio.create_subprocess_shell('x')\n",
    "os.system": "import os\nos.system('x')\n",
    "os.popen": "import os\nos.popen('x')\n",
    "os.spawnl": "import os\nos.spawnl\n",
    "os.spawnle": "import os\nos.spawnle\n",
    "os.spawnlp": "import os\nos.spawnlp\n",
    "os.spawnlpe": "import os\nos.spawnlpe\n",
    "os.spawnv": "import os\nos.spawnv\n",
    "os.spawnve": "import os\nos.spawnve\n",
    "os.spawnvp": "import os\nos.spawnvp\n",
    "os.spawnvpe": "import os\nos.spawnvpe\n",
    "os.execl": "import os\nos.execl\n",
    "os.execle": "import os\nos.execle\n",
    "os.execlp": "import os\nos.execlp\n",
    "os.execlpe": "import os\nos.execlpe\n",
    "os.execv": "import os\nos.execv\n",
    "os.execve": "import os\nos.execve\n",
    "os.execvp": "import os\nos.execvp\n",
    "os.execvpe": "import os\nos.execvpe\n",
    "os.posix_spawn": "from os import posix_spawn\n",
    "os.posix_spawnp": "from os import posix_spawnp\n",
    "os.fork": "import os\nos.fork()\n",
    "os.forkpty": "import os\nos.forkpty()\n",
    "os.startfile": "import os\nos.startfile\n",
    "posix": "import posix\n",
    "_posixsubprocess": "import _posixsubprocess\n",
    "pty": "import pty\n",
    "multiprocessing": "import multiprocessing\n",
    "pickle": "import pickle\n",
    "marshal": "import marshal\n",
    "importlib.import_module": "import importlib\nimportlib.import_module('os')\n",
    "builtins": "import builtins\nbuiltins.__import__('os')\n",
}

# Names ruff's banned-api cannot see; `test_no_dynamic_import_builtin` scans for them.
# `__builtins__` is reachable in every module without an import.
UNSCANNABLE_BUILTINS = frozenset({"__import__", "__builtins__"})


def banned_entries() -> set[str]:
    data = tomllib.loads((REPO_ROOT / "pyproject.toml").read_text(encoding="utf-8"))
    return set(data["tool"]["ruff"]["lint"]["flake8-tidy-imports"]["banned-api"])


def ruff_tid251(source: str, filename: str) -> list[dict[str, object]]:
    """Lint `source` as if it were `filename` and return the TID251 diagnostics."""
    proc = subprocess.run(
        [
            sys.executable, "-m", "ruff", "check", "--no-cache", "--select", "TID251",
            "--output-format", "json", "--stdin-filename", filename, "-",
        ],
        input=source,
        capture_output=True,
        text=True,
        cwd=REPO_ROOT,
        check=False,
        timeout=60,
    )  # fmt: skip
    assert proc.returncode in (0, 1), proc.stderr
    diagnostics: list[dict[str, object]] = json.loads(proc.stdout)
    return [d for d in diagnostics if d.get("code") == "TID251"]


def test_every_banned_entry_has_a_case() -> None:
    assert set(CASES) == banned_entries()


@pytest.mark.parametrize(("entry", "source"), sorted(CASES.items()))
def test_banned_entry_is_reported(entry: str, source: str) -> None:
    diagnostics = ruff_tid251(source, CHECKED_PATH)
    messages = [str(d["message"]) for d in diagnostics]
    assert any(f"`{entry}`" in m for m in messages), messages


def builtin_uses(source: str, names: frozenset[str]) -> list[int]:
    """Return the lines where `source` refers to one of the builtin `names`."""
    return [
        node.lineno
        for node in ast.walk(ast.parse(source))
        if isinstance(node, ast.Name) and node.id in names
    ]


def test_no_dynamic_import_builtin() -> None:
    """ruff cannot ban the `__import__` builtin, so scan every module for it."""
    offenders = {
        str(path.relative_to(REPO_ROOT)): lines
        for path in sorted((REPO_ROOT / "src" / "aipm").rglob("*.py"))
        if (lines := builtin_uses(path.read_text(encoding="utf-8"), UNSCANNABLE_BUILTINS))
    }
    assert offenders == {}


@pytest.mark.parametrize(
    "source",
    ["x = __import__('subprocess')\n", "x = __builtins__['__import__']('subprocess')\n"],
)
def test_dynamic_import_scan_catches_a_use(source: str) -> None:
    assert builtin_uses(source, UNSCANNABLE_BUILTINS) == [1]


def test_process_module_is_the_only_exemption() -> None:
    assert ruff_tid251("import subprocess\n", EXEMPT_PATH) == []
    # The same code one file over is still banned.
    assert ruff_tid251("import subprocess\n", "src/aipm/execution/git.py")


def test_violating_fixture_is_fully_reported() -> None:
    fixture = Path(__file__).parent / "fixtures" / "banned_apis.py"
    diagnostics = ruff_tid251(fixture.read_text(encoding="utf-8"), CHECKED_PATH)
    flagged_lines = {d["location"]["row"] for d in diagnostics}  # type: ignore[index]
    source = fixture.read_text(encoding="utf-8")
    allowed = {"import asyncio", "import importlib", "import os"}
    code_lines = {
        number
        for number, line in enumerate(source.splitlines(), start=1)
        if line and not line.startswith("#") and line not in allowed
    }
    # Importing os, asyncio or importlib is fine. Every other line is a violation, reported by
    # ruff, or for the bare `__import__` builtin, by the AST scan.
    caught = flagged_lines | set(builtin_uses(source, UNSCANNABLE_BUILTINS))
    assert code_lines <= caught, sorted(code_lines - caught)
