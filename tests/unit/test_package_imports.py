"""Every module in the package imports cleanly, with no cycles or missing names.

The skeleton's stubs raise NotImplementedError when called; importing them must still work.
"""

import importlib
import pkgutil

import pytest

import aipm

GENERATED = {"aipm._version"}  # written by hatch-vcs at build time
MODULES = sorted(
    info.name
    for info in pkgutil.walk_packages(aipm.__path__, prefix="aipm.")
    if info.name not in GENERATED
)


def test_the_package_has_the_expected_top_level_packages() -> None:
    top = {name.split(".")[1] for name in MODULES}
    assert top >= {
        "cli", "app", "domain", "security", "state", "config", "llm", "roles", "context",
        "adapters", "execution", "gates", "scanners", "reporting", "observability", "plugins",
    }  # fmt: skip


@pytest.mark.parametrize("name", MODULES)
def test_module_imports(name: str) -> None:
    module = importlib.import_module(name)
    assert module.__doc__, f"{name} has no docstring"
