"""Entry-point plugins load only from aipm's own environment (ARCHITECTURE §18, build prompt 08).

Each fake plugin here writes a marker file when it is imported, so a test can prove its code
never ran, not only that it was not listed.
"""

import os
import sys
from collections.abc import Iterator
from pathlib import Path

import pytest

from aipm.plugins import loader

STACK_YAML = """\
allowed_executables:
  - [make, test]
gates:
  unit: {run: [make, test], required: true}
"""


def install(site: Path, dist: str, module: str, entry_points: str, marker: Path) -> None:
    """A distribution in `site`: its metadata, its entry points, and a module that writes
    `marker` when it is imported."""
    info = site / f"{dist}-0.1.dist-info"
    info.mkdir(parents=True)
    (info / "METADATA").write_text(
        f"Metadata-Version: 2.1\nName: {dist}\nVersion: 0.1\n", encoding="utf-8"
    )
    (info / "entry_points.txt").write_text(entry_points, encoding="utf-8")
    (site / f"{module}.py").write_text(
        f"from pathlib import Path\nPath({str(marker)!r}).write_text('ran')\n"
        f"STACK = {STACK_YAML!r}\nADAPTER = object()\n",
        encoding="utf-8",
    )


@pytest.fixture(autouse=True)
def clean_modules() -> Iterator[None]:
    before = set(sys.modules)
    saved = list(sys.path)
    yield
    for name in set(sys.modules) - before:
        if name.startswith(("good_plugin", "evil_plugin", "shadow_plugin")):
            del sys.modules[name]
    sys.path[:] = saved
    loader.configure(enabled=True)


def test_a_plugin_in_aipms_own_environment_is_loaded(tmp_path: Path) -> None:
    site = tmp_path / "site"
    marker = tmp_path / "ran"
    install(site, "good-plugin", "good_plugin",
            "[aipm.stacks]\nmakefile = good_plugin:STACK\n", marker)  # fmt: skip
    found = loader.load_plugins(enabled=True, paths=[site])
    (plugin,) = found.plugins
    assert (plugin.group, plugin.name, plugin.distribution, plugin.version) == (
        "aipm.stacks",
        "makefile",
        "good-plugin",
        "0.1",
    )
    assert plugin.obj == STACK_YAML and marker.exists()
    assert plugin.to_data()["target"] == "good_plugin:STACK"


def test_no_plugins_loads_nothing(tmp_path: Path) -> None:
    site = tmp_path / "site"
    marker = tmp_path / "ran"
    install(site, "good-plugin", "good_plugin", "[aipm.stacks]\nx = good_plugin:STACK\n", marker)
    found = loader.load_plugins(enabled=False, paths=[site])
    assert (found.enabled, found.plugins) == (False, ())
    assert not marker.exists()


def test_a_plugin_in_the_target_repos_virtualenv_is_not_loaded(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The repository's `.venv` is on PYTHONPATH, on sys.path and the current directory: aipm
    reads distributions only from its own interpreter's site-packages."""
    repo = tmp_path / "repo"
    site = repo / ".venv" / "lib" / "python3.13" / "site-packages"
    marker = tmp_path / "evil-ran"
    install(site, "evil-plugin", "evil_plugin",
            "[aipm.adapters]\ncursor = evil_plugin:ADAPTER\n"
            "[aipm.stacks]\nevil = evil_plugin:STACK\n", marker)  # fmt: skip
    monkeypatch.chdir(repo)
    monkeypatch.setenv("PYTHONPATH", str(site))
    monkeypatch.syspath_prepend(str(site))
    sys.path.insert(0, "")
    found = loader.load_plugins(enabled=True, repo=repo)
    assert all(p.distribution != "evil-plugin" for p in found.plugins)
    assert not marker.exists()
    assert all(not loader._inside(p, repo) for p in loader.own_paths())  # pyright: ignore[reportPrivateUsage]


def test_aipm_installed_inside_the_repository_loads_no_plugin(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    site = repo / ".venv" / "site-packages"
    marker = tmp_path / "ran"
    install(site, "evil-plugin", "evil_plugin", "[aipm.stacks]\nevil = evil_plugin:STACK\n",
            marker)  # fmt: skip
    found = loader.load_plugins(enabled=True, repo=repo, paths=[site])
    assert found.plugins == ()
    assert "inside the repository" in found.warnings[0]
    assert not marker.exists()


def test_a_module_that_only_the_current_directory_holds_is_never_imported(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A real distribution names `shadow_plugin`, but the module exists only in the cwd (as
    `python -m aipm` would put it on sys.path): the import cannot see it."""
    site = tmp_path / "site"
    marker = tmp_path / "shadow-ran"
    install(site, "shadow-plugin", "unused_module",
            "[aipm.stacks]\nshadow = shadow_plugin:STACK\n", tmp_path / "unused")  # fmt: skip
    cwd = tmp_path / "cwd"
    cwd.mkdir()
    (cwd / "shadow_plugin.py").write_text(
        f"from pathlib import Path\nPath({str(marker)!r}).write_text('ran')\nSTACK = ''\n"
    )
    monkeypatch.chdir(cwd)
    sys.path.insert(0, "")
    sys.path.insert(0, str(cwd))
    found = loader.load_plugins(enabled=True, paths=[site])
    assert found.plugins == ()
    assert "ModuleNotFoundError" in found.warnings[0]
    assert not marker.exists()


@pytest.mark.parametrize(
    ("entry", "reason"),
    [
        ("[aipm.adapters]\nclaude = good_plugin:ADAPTER\n", "taken"),
        ("[aipm.stacks]\nBad_Name = good_plugin:STACK\n", "plain lower-case"),
        ("[aipm.stacks]\nok = good_plugin:STACK; rm -rf /\n", "not a plain module"),
        ("[aipm.stacks]\nok = good_plugin:MISSING\n", "AttributeError"),
    ],
)
def test_bad_plugins_are_skipped_with_a_warning(tmp_path: Path, entry: str, reason: str) -> None:
    site = tmp_path / "site"
    install(site, "good-plugin", "good_plugin", entry, tmp_path / "ran")
    found = loader.load_plugins(enabled=True, paths=[site])
    assert found.plugins == ()
    assert reason in found.warnings[0], found.warnings


def test_other_groups_are_ignored(tmp_path: Path) -> None:
    site = tmp_path / "site"
    marker = tmp_path / "ran"
    install(site, "good-plugin", "good_plugin",
            "[console_scripts]\ngood = good_plugin:STACK\n", marker)  # fmt: skip
    assert loader.load_plugins(enabled=True, paths=[site]).plugins == ()
    assert not marker.exists()


def test_the_loader_is_lazy_and_configured_per_run(tmp_path: Path) -> None:
    loader.configure(enabled=False, repo=tmp_path)
    assert loader.loaded().enabled is False
    loader.configure(enabled=True, repo=tmp_path)
    assert loader.loaded().enabled is True
    assert loader.loaded() is loader.loaded()


def test_a_plugin_stack_is_listed_and_validated(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from aipm.config import stacks  # noqa: PLC0415

    site = tmp_path / "site"
    install(site, "good-plugin", "good_plugin",
            "[aipm.stacks]\nmakefile = good_plugin:STACK\npython-uv = good_plugin:STACK\n",
            tmp_path / "ran")  # fmt: skip
    found = loader.load_plugins(enabled=True, paths=[site])
    monkeypatch.setattr(loader, "loaded", lambda: found)
    assert stacks.available_stacks()[-1] == "makefile"
    assert stacks.available_stacks().count("python-uv") == 1  # a shipped name is never replaced
    assert tuple(stacks.load_stack("makefile").gates["unit"].run or ()) == ("make", "test")
    assert os.fspath(site) in found.paths
