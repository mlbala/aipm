"""The v0.4 decisions, session 4: the low findings left open at the end of session 3.

1. A pnpm gate and a committed `verifyDepsBeforeRun: install`.
2. `cacheDir`, `virtualStoreDir` and `modulesDir` in `pnpm-workspace.yaml`.
3. `aipm trust --show` lists `pnpm-workspace.yaml`'s settings.
4. Release verification pins the signer certificate exactly (`--cert-identity`).
5. Dependabot covers every locked dependency set under `.github/`.
"""

from pathlib import Path

from ruamel.yaml import YAML

from tests.conftest import REPO_ROOT

# ---------------------------------------------------------------- 5: Dependabot

LOCKFILE_ECOSYSTEMS = {
    "package-lock.json": "npm",
    "uv.lock": "uv",
    "requirements-build.txt": "pip",
}
"""A locked or hash-pinned dependency file under `.github/`, and the ecosystem that updates it."""


def _dependabot_entries() -> set[tuple[str, str]]:
    doc = YAML(typ="safe", pure=True).load((REPO_ROOT / ".github" / "dependabot.yml").read_text())
    return {(u["package-ecosystem"], u["directory"].rstrip("/") or "/") for u in doc["updates"]}


def test_every_locked_dependency_set_under_github_has_a_dependabot_entry() -> None:
    """The sandbox job's `package-lock.json` (srt, pnpm) had none, so it got no updates."""
    entries = _dependabot_entries()
    found = [
        path
        for path in sorted((REPO_ROOT / ".github").rglob("*"))
        if path.name in LOCKFILE_ECOSYSTEMS and "node_modules" not in path.parts
    ]
    assert found, "no lockfile found under .github/"
    for path in found:
        directory = "/" + str(path.parent.relative_to(REPO_ROOT))
        assert (LOCKFILE_ECOSYSTEMS[path.name], directory) in entries, path


def test_every_dependabot_entry_waits_a_week() -> None:
    doc = YAML(typ="safe", pure=True).load((REPO_ROOT / ".github" / "dependabot.yml").read_text())
    for update in doc["updates"]:
        assert update["cooldown"]["default-days"] >= 7, update["directory"]
        assert update["commit-message"]["prefix"] == "chore", update["directory"]


def test_the_root_lockfile_stays_covered() -> None:
    assert ("uv", "/") in _dependabot_entries()
    assert Path(REPO_ROOT / "uv.lock").is_file()


# ---------------------------------------------------------------- 4: exact signer identity

SIGNER = "https://github.com/mlbala/aipm/.github/workflows/release.yml@refs/tags/"


def test_install_sh_and_the_readme_pin_the_exact_signer_identity() -> None:
    """`--signer-workflow` may match more than one workflow path; `--cert-identity` is exact,
    and gh refuses the two together, so neither command may name `--signer-workflow`."""
    install = (REPO_ROOT / "install.sh").read_text(encoding="utf-8")
    readme = (REPO_ROOT / "README.md").read_text(encoding="utf-8")
    assert f'--cert-identity "{SIGNER}$TAG"' in install
    assert f"--cert-identity {SIGNER}v" in readme
    for text in (install, readme):
        assert "--signer-workflow mlbala" not in text
        assert "--cert-identity-regex" not in text
