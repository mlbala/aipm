"""The settings in a repository's `pnpm-workspace.yaml` (pnpm 10), which beat the environment.

Read for `aipm trust --show`, which lists them (the file itself is hashed into the trust
surface, ADR-0032), and for gates that run pnpm, which are refused when the file makes pnpm
install before running a script (`verifyDepsBeforeRun`). The file is repository text: it is
parsed with aipm's safe YAML loader and only ever shown as data.
"""

import errno
import os
import re
import stat
from pathlib import Path

from aipm.domain.errors import PolicyViolation, SchemaError
from aipm.state.yamlio import MAX_YAML_BYTES, load_yaml

PNPM_WORKSPACE = "pnpm-workspace.yaml"
NPMRC = ".npmrc"

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
    data = _read_small(root, PNPM_WORKSPACE)
    if data is None:
        return None
    try:
        return load_settings(data)
    except SchemaError as exc:
        raise _unreadable(PNPM_WORKSPACE, exc.message) from None


_VERIFY_KEY = "verifydepsbeforerun"
_EXPANDS_WITH_DEFAULT = re.compile(r"\$\{[^}]*-")
"""`${VAR:-default}` (or `${VAR-default}`): pnpm expands `.npmrc` keys and values from the
environment, and a default can name any setting or value."""


def npmrc_installs(root: Path) -> bool:
    """Whether `root/.npmrc` may make pnpm install before a script (`verify-deps-before-run`
    other than `error`, `warn` or `false`). Read as npm's ini format, failing closed: every line
    in every section, keys compared without case, `-` or `_` (pnpm also reads the camel-case
    spelling), a key with an expansion default or a value with any expansion counts as
    installing. Exit 6 when the file cannot be read, as for `read_settings`."""
    data = _read_small(root, NPMRC)
    if data is None:
        return False
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError:
        raise _unreadable(NPMRC, "it is not UTF-8") from None
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line[0] in "#;" or (line[0] == "[" and line[-1] == "]"):
            continue
        key, equals, value = line.partition("=")
        key = _unquote(key).removesuffix("[]")
        if _EXPANDS_WITH_DEFAULT.search(key):
            return True
        if re.sub(r"[-_]", "", key).casefold() != _VERIFY_KEY:
            continue
        value = _unquote(value).casefold() if equals else "true"
        if "${" in value or value not in SAFE_VERIFY_DEPS:
            return True
    return False


def _unquote(text: str) -> str:
    text = text.strip()
    if len(text) >= 2 and text[0] == text[-1] and text[0] in "'\"":
        return text[1:-1].strip()
    return text


def _read_small(root: Path, name: str) -> bytes | None:
    """`root/name`, or `None` when there is none. Exit 6 for a link, anything but a regular
    file, or a file over 1 MiB."""
    try:
        fd = os.open(root / name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)  # FIFO-safe
    except FileNotFoundError:
        return None
    except OSError as exc:
        if exc.errno == errno.ELOOP:
            raise _unreadable(name, "it is a symbolic link") from None
        raise _unreadable(name, exc.strerror or "it cannot be opened") from None
    if not stat.S_ISREG(os.fstat(fd).st_mode):
        os.close(fd)
        raise _unreadable(name, "it is not a regular file")
    with os.fdopen(fd, "rb") as handle:
        data = handle.read(MAX_YAML_BYTES + 1)
    if len(data) > MAX_YAML_BYTES:
        raise _unreadable(name, "it is larger than 1 MiB")
    return data


def _unreadable(name: str, why: str) -> PolicyViolation:
    kind = "YAML " if name == PNPM_WORKSPACE else ""
    return PolicyViolation(
        f"the repository's {name} cannot be checked before a gate that may run pnpm ({why})",
        hint=f"Commit {name} as a regular {kind}file of at most 1 MiB, or remove it.",
    )
