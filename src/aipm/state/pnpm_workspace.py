"""The settings in a repository's `pnpm-workspace.yaml` (pnpm 10), which beat the environment.

Read for `aipm trust --show`, which lists them (the file itself is hashed into the trust
surface, ADR-0032), and for gates that run pnpm, which are refused when the file makes pnpm
install before running a script (`verifyDepsBeforeRun`). The file is repository text: it is
parsed with aipm's safe YAML loader and only ever shown as data.
"""

import errno
import os
import stat
from pathlib import Path

from aipm.domain.errors import PolicyViolation, SchemaError
from aipm.state.yamlio import MAX_YAML_BYTES, load_yaml

PNPM_WORKSPACE = "pnpm-workspace.yaml"

NOT_SETTINGS = frozenset({"packages", "catalog", "catalogs"})
"""Top-level keys that list workspace packages or dependency versions, not settings."""

RISKY = frozenset(
    {
        # Code that runs, or decides what runs, during install.
        "configDependencies", "dangerouslyAllowAllBuilds", "onlyBuiltDependencies",
        "onlyBuiltDependenciesFile", "neverBuiltDependencies", "enablePrePostScripts",
        "ignoreScripts", "pnpmfile", "globalPnpmfile", "ignorePnpmfile", "scriptShell",
        "shellEmulator", "unsafePerm", "sideEffectsCache", "executionEnv", "useNodeVersion",
        "verifyDepsBeforeRun",
        # What gets installed, and from where.
        "overrides", "packageExtensions", "patchedDependencies", "registry", "registries",
        "strictSsl", "ca", "cafile", "minimumReleaseAge", "minimumReleaseAgeExclude",
        "trustPolicy",
        # Where pnpm writes, and how it links.
        "storeDir", "packageImportMethod", "cacheDir", "virtualStoreDir", "modulesDir",
        "stateDir", "nodeLinker", "lockfileDir", "enableGlobalVirtualStore", "globalDir",
        "globalBinDir", "pnpmHomeDir",
        # The network, and pnpm's own version.
        "httpProxy", "httpsProxy", "proxy", "noproxy", "managePackageManagerVersions",
        "nodeOptions",
    }
)  # fmt: skip
"""Settings that change what pnpm installs or runs, or where it writes; `trust --show` marks
them. Every other setting is listed too."""

SAFE_VERIFY_DEPS = (False, "false", "warn", "error")
"""`verifyDepsBeforeRun` values that never install: anything else (`install`, `prompt`, a value
pnpm adds later) is refused for a pnpm gate."""


def load_settings(data: bytes) -> dict[str, object]:
    """The file's top-level settings, without `packages` and the catalogs. Raises
    `SchemaError` when it is not UTF-8, not YAML aipm reads, or not a mapping."""
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError:
        raise SchemaError(f"{PNPM_WORKSPACE} is not UTF-8") from None
    doc = load_yaml(text, source=PNPM_WORKSPACE)
    if doc is None:
        return {}
    if not isinstance(doc, dict):
        raise SchemaError(f"{PNPM_WORKSPACE} is not a mapping")
    items: dict[object, object] = doc  # pyright: ignore[reportUnknownVariableType]
    return {str(key): value for key, value in items.items() if str(key) not in NOT_SETTINGS}


def expanded(key: str) -> bool:
    """Whether pnpm would expand `key` from the environment (`${VAR:-default}`), so aipm
    cannot tell which setting it names."""
    return "${" in key


def is_risky(key: str) -> bool:
    return key in RISKY or expanded(key)


def installs_before_run(settings: dict[str, object]) -> bool:
    """Whether pnpm might install before `pnpm test`, `run` or `exec` (pnpm 10): a
    `verifyDepsBeforeRun` that is not `error`, `warn` or `false`, or any key pnpm expands."""
    if any(expanded(key) for key in settings):
        return True
    for key in ("verifyDepsBeforeRun", "verify-deps-before-run"):
        if key in settings and settings[key] not in SAFE_VERIFY_DEPS:
            return True
    return False


def read_settings(root: Path) -> dict[str, object] | None:
    """The settings of `root/pnpm-workspace.yaml`, or `None` when there is none. Exit 6 for a
    link, anything but a regular file, a file over 1 MiB, or one aipm cannot parse: pnpm would
    still read it, so a check that relies on it fails closed."""
    path = root / PNPM_WORKSPACE
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)  # a FIFO never blocks
    except FileNotFoundError:
        return None
    except OSError as exc:
        if exc.errno == errno.ELOOP:
            raise _unreadable("it is a symbolic link") from None
        raise _unreadable(exc.strerror or "it cannot be opened") from None
    if not stat.S_ISREG(os.fstat(fd).st_mode):
        os.close(fd)
        raise _unreadable("it is not a regular file")
    with os.fdopen(fd, "rb") as handle:
        data = handle.read(MAX_YAML_BYTES + 1)
    if len(data) > MAX_YAML_BYTES:
        raise _unreadable("it is larger than 1 MiB")
    try:
        return load_settings(data)
    except SchemaError as exc:
        raise _unreadable(exc.message) from None


def _unreadable(why: str) -> PolicyViolation:
    return PolicyViolation(
        f"the repository's {PNPM_WORKSPACE} cannot be checked before a pnpm gate runs ({why})",
        hint=f"Commit {PNPM_WORKSPACE} as a regular YAML file of at most 1 MiB, or remove it.",
    )
