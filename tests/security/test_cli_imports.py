"""The CLI imports only what ARCHITECTURE §5.1 allows: an allow-list, not a deny-list.

`aipm.cli` may import `aipm.app`, `aipm.domain.errors`, `aipm.security.sanitize`, its own
modules and `aipm.__version__`. A new `domain` or `security` module is therefore not allowed by
default (step 01 security review, finding 7). Lazy imports inside functions count too.
"""

import ast
from pathlib import Path

import pytest

from tests.conftest import REPO_ROOT

CLI = REPO_ROOT / "src" / "aipm" / "cli"
ALLOWED_PREFIXES = ("aipm.cli", "aipm.app")
ALLOWED_MODULES = {"aipm", "aipm.domain.errors", "aipm.security.sanitize"}


def allowed(module: str) -> bool:
    if module in ALLOWED_MODULES:
        return True
    return any(module == prefix or module.startswith(f"{prefix}.") for prefix in ALLOWED_PREFIXES)


def aipm_imports(source: str) -> list[tuple[int, str]]:
    """Every `aipm` module a source file imports, with its line."""
    found: list[tuple[int, str]] = []
    for node in ast.walk(ast.parse(source)):
        if isinstance(node, ast.Import):
            found.extend((node.lineno, alias.name) for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.level > 0:
            # Relative imports would dodge the prefixes below; the CLI uses none.
            found.append((node.lineno, f"aipm.<relative import, level {node.level}>"))
        elif isinstance(node, ast.ImportFrom) and node.module:
            for alias in node.names:
                full = f"{node.module}.{alias.name}"
                # `from aipm.app import init` and `from aipm import state` import modules;
                # `from aipm import __version__` imports the one allowed package name.
                if node.module == "aipm" and alias.name == "__version__":
                    found.append((node.lineno, "aipm"))
                elif node.module in ("aipm", "aipm.app", "aipm.domain", "aipm.security"):
                    found.append((node.lineno, full))
                else:
                    found.append((node.lineno, node.module))
    return [(line, name) for line, name in found if name == "aipm" or name.startswith("aipm.")]


def offenders(source: str) -> list[str]:
    return [f"{line}: {name}" for line, name in aipm_imports(source) if not allowed(name)]


def test_cli_imports_only_allowed_modules() -> None:
    problems = {
        str(path.relative_to(REPO_ROOT)): found
        for path in sorted(CLI.rglob("*.py"))
        if (found := offenders(path.read_text(encoding="utf-8")))
    }
    assert problems == {}


@pytest.mark.parametrize(
    "source",
    [
        "import aipm.state.store\n",
        "from aipm.domain import ids\n",
        "from aipm.domain.models import Task\n",
        "from aipm.security.paths import safe_relpath\n",
        "from aipm.security.new_module import x\n",
        "def f():\n    from aipm.config.loader import load_config\n",
        "from ..security import new_module\n",
        "from . import output\n",
        "from aipm import state\n",
        "from aipm.security import paths\n",
    ],
)
def test_the_allow_list_catches_violations(source: str) -> None:
    assert offenders(source)


@pytest.mark.parametrize(
    "source",
    [
        "from aipm import __version__\n",
        "from aipm.app import init as use_case\n",
        "from aipm.domain.errors import AipmError\n",
        "from aipm.security.sanitize import sanitize_text\n",
        "from aipm.security import sanitize\n",
        "from aipm.domain import errors\n",
        "from aipm.cli.output import fail\n",
        "import typer\n",
    ],
)
def test_the_allow_list_accepts_what_is_allowed(source: str) -> None:
    assert offenders(source) == []


def test_cli_package_exists() -> None:
    assert (CLI / "main.py").is_file()
    assert Path(CLI / "output.py").is_file()
