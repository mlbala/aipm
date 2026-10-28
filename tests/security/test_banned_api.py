"""Nothing outside execution/process.py can start a process or import dynamically.

ARCHITECTURE §5.1, SECURITY.md §10 rule 1, AGENTS.md rule 1. Two layers:

- ruff's banned-api rule (TID251). The list is read from pyproject.toml, so an entry without a
  test case fails `test_every_banned_entry_has_a_case`.
- An AST scan for what ruff cannot see: the `__import__` and `__builtins__` names, event-loop
  `subprocess_exec`/`subprocess_shell`, `sys.modules[...]`, and `getattr(x, "<banned name>")`.

`execution/process.py` is the only exemption, through line-level `# noqa: TID251` comments.
"""

import ast
import json
import re
import subprocess
import sys
import tomllib
from pathlib import Path

import pytest

from tests.conftest import REPO_ROOT

SRC = REPO_ROOT / "src" / "aipm"
PROCESS_MODULE = SRC / "execution" / "process.py"
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
    "concurrent.futures.ProcessPoolExecutor": (
        "from concurrent.futures import ProcessPoolExecutor\n"
    ),
    "ctypes": "import ctypes\n",
    "webbrowser": "import webbrowser\n",
    "pydoc": "import pydoc\n",
    "runpy": "import runpy\n",
    "code": "import code\n",
    "codeop": "import codeop\n",
    "pickle": "import pickle\n",
    "marshal": "import marshal\n",
    "importlib.import_module": "import importlib\nimportlib.import_module('os')\n",
    "importlib.__import__": "import importlib\nimportlib.__import__('os')\n",
    "importlib.util": "import importlib.util\n",
    "importlib.machinery": "import importlib.machinery\n",
    "builtins": "import builtins\nbuiltins.__import__('os')\n",
}

# Names and attributes ruff's banned-api cannot see.
HIDDEN_NAMES = frozenset({"__import__", "__builtins__"})
LOOP_ATTRIBUTES = frozenset({"subprocess_exec", "subprocess_shell"})
GETATTR_TARGETS = frozenset(
    {
        "system", "popen", "fork", "forkpty", "posix_spawn", "posix_spawnp", "startfile",
        "spawnl", "spawnle", "spawnlp", "spawnlpe", "spawnv", "spawnve", "spawnvp", "spawnvpe",
        "execl", "execle", "execlp", "execlpe", "execv", "execve", "execvp", "execvpe",
        "import_module", "create_subprocess_exec", "create_subprocess_shell",
        "subprocess_exec", "subprocess_shell", "__import__", "__builtins__",
    }
)  # fmt: skip


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


def unscannable_uses(source: str) -> list[int]:
    """Return the lines that use a process or dynamic-import route ruff cannot see."""
    lines: list[int] = []
    for node in ast.walk(ast.parse(source)):
        hit = (
            (isinstance(node, ast.Name) and node.id in HIDDEN_NAMES)
            or (isinstance(node, ast.Constant) and node.value in HIDDEN_NAMES)
            or (isinstance(node, ast.Attribute) and node.attr in LOOP_ATTRIBUTES)
            or (
                isinstance(node, ast.Subscript)
                and isinstance(node.value, ast.Attribute)
                and node.value.attr == "modules"
                and isinstance(node.value.value, ast.Name)
                and node.value.value.id == "sys"
            )
            or (
                isinstance(node, ast.Call)
                and isinstance(node.func, ast.Name)
                and node.func.id == "getattr"
                and len(node.args) >= 2
                and isinstance(node.args[1], ast.Constant)
                and node.args[1].value in GETATTR_TARGETS
            )
        )
        if hit:
            lines.append(node.lineno)
    return sorted(set(lines))


def package_modules() -> list[Path]:
    return sorted(p for p in SRC.rglob("*.py") if "__pycache__" not in p.parts)


def test_every_banned_entry_has_a_case() -> None:
    assert set(CASES) == banned_entries()


@pytest.mark.parametrize(("entry", "source"), sorted(CASES.items()))
def test_banned_entry_is_reported(entry: str, source: str) -> None:
    diagnostics = ruff_tid251(source, CHECKED_PATH)
    messages = [str(d["message"]) for d in diagnostics]
    assert any(f"`{entry}`" in m for m in messages), messages


def test_process_module_has_no_file_wide_exemption() -> None:
    """process.py may import subprocess only on lines marked `# noqa: TID251`."""
    assert ruff_tid251("import pickle\n", EXEMPT_PATH)
    assert ruff_tid251("import subprocess\n", EXEMPT_PATH)
    assert ruff_tid251("import subprocess  # noqa: TID251\n", EXEMPT_PATH) == []


def test_lint_suppressions_appear_only_where_allowed() -> None:
    """No blanket `# noqa`, no file-level `ruff: noqa`, and TID251 noqa only in process.py."""
    blanket = re.compile(r"#\s*noqa(?!:)", re.IGNORECASE)
    file_level = re.compile(r"#\s*(ruff|flake8)\s*:\s*noqa", re.IGNORECASE)
    tid251 = re.compile(r"#\s*noqa:[^\n]*TID251", re.IGNORECASE)
    offenders: list[str] = []
    for path in package_modules():
        for number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), start=1):
            where = f"{path.relative_to(REPO_ROOT)}:{number}"
            if blanket.search(line) or file_level.search(line):
                offenders.append(where)
            if tid251.search(line) and path != PROCESS_MODULE:
                offenders.append(where)
    assert offenders == []


def test_no_unscannable_process_routes_in_the_package() -> None:
    offenders = {
        str(path.relative_to(REPO_ROOT)): lines
        for path in package_modules()
        if path != PROCESS_MODULE and (lines := unscannable_uses(path.read_text(encoding="utf-8")))
    }
    assert offenders == {}


@pytest.mark.parametrize(
    "source",
    [
        "x = __import__('subprocess')\n",
        "x = __builtins__['__import__']('subprocess')\n",
        "x = globals()['__builtins__']\n",
        "loop.subprocess_exec(factory, 'sh')\n",
        "import sys\nx = sys.modules['subprocess']\n",
        "import os\nx = getattr(os, 'system')\n",
    ],
)
def test_the_scan_catches_each_route(source: str) -> None:
    assert unscannable_uses(source) == [source.count("\n")]


def test_violating_fixture_is_fully_reported() -> None:
    fixture = REPO_ROOT / "tests" / "security" / "fixtures" / "banned_apis.py"
    source = fixture.read_text(encoding="utf-8")
    flagged = {int(d["location"]["row"]) for d in ruff_tid251(source, CHECKED_PATH)}  # type: ignore[index]
    allowed = {"import asyncio", "import importlib", "import os", "import sys"}
    code_lines = {
        number
        for number, line in enumerate(source.splitlines(), start=1)
        if line and not line.startswith("#") and line not in allowed
    }
    # Every other line is a violation, reported by ruff or by the AST scan.
    caught = flagged | set(unscannable_uses(source))
    assert code_lines <= caught, sorted(code_lines - caught)


def test_fixtures_directory_holds_only_known_files() -> None:
    """A conftest.py hidden here would run under pytest without being linted."""
    fixtures = REPO_ROOT / "tests" / "security" / "fixtures"
    names = {p.name for p in fixtures.iterdir() if p.name != "__pycache__"}
    assert names == {"README.md", "banned_apis.py"}
