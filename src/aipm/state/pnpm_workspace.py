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
from aipm.security.json_limits import loads_bounded
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
    other than `error`, `warn` or `false`). Each line is read as npm's `ini` package reads it
    (`_ini_line`), then checked failing closed: every section, keys compared without case, `-`
    or `_` (pnpm also reads the camel-case spelling), a bare key as `true`, a key with an
    expansion default or a value with any expansion as installing; and any other line that
    spells the setting's letters is refused unless it is a safe assignment. Exit 6 when the file
    cannot be read, as for `read_settings`."""
    data = _read_small(root, NPMRC)
    if data is None:
        return False
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError:
        raise _unreadable(NPMRC, "it is not UTF-8") from None
    for line in _NEWLINES.split(text):
        if _ini_ignores(line):
            continue
        spells = _VERIFY_KEY in re.sub(r"[^a-z]", "", line.casefold())
        parsed = _ini_line(line)
        if parsed is None:
            if spells:
                return True  # a line `ini` skips, which aipm cannot be sure pnpm skips
            continue
        key, value = parsed
        if _EXPANDS_WITH_DEFAULT.search(key):
            return True
        setting = re.sub(r"[-_]", "", key).casefold() == _VERIFY_KEY
        if (setting and not _safe_verify(value)) or (spells and not setting):
            return True  # an installing value, or the setting's letters in another spelling
    return False


_JS_SPACE = (
    "\t\n\v\f\r \u00a0\u1680\u2000\u2001\u2002\u2003\u2004\u2005\u2006\u2007\u2008"
    "\u2009\u200a\u2028\u2029\u202f\u205f\u3000\ufeff"
)
"""JavaScript's `\\s` and `trim()`: unlike Python's `str.strip()`, they include U+FEFF."""
_NEWLINES = re.compile(r"[\r\n]+")
_SECTION = re.compile(rf"\[[^\]]*\][{_JS_SPACE}]*")
_JSON_WORDS: dict[str, object] = {"true": True, "false": False, "null": None}
"""The unquoted values `ini` turns into JSON's literals."""
_ASSIGNMENT = re.compile(r"([^=]+)(=([^\n\r\u2028\u2029]*))?")
"""`ini`'s line pattern; JavaScript's `.` matches no line terminator."""


def _ini_ignores(line: str) -> bool:
    """A blank line, a comment or a section header, which `ini.decode` sets nothing from."""
    if not line.strip(_JS_SPACE) or line.lstrip(_JS_SPACE)[:1] in ("#", ";"):
        return True
    return line.startswith("[") and _SECTION.fullmatch(line) is not None


def _ini_line(line: str) -> tuple[str, object] | None:
    """`(key, value)` as `ini.decode` (npm's `ini` 4) reads one line that `_ini_ignores` does
    not, or `None` for a line it skips. A key that is not a string after `JSON.parse` names no
    setting."""
    match = _ASSIGNMENT.fullmatch(line)
    if match is None:
        return None
    key = _ini_unsafe(match.group(1))
    if not isinstance(key, str):
        return None
    if len(key) > 2 and key.endswith("[]"):
        key = key[:-2]
    value: object = _ini_unsafe(match.group(3)) if match.group(2) is not None else True
    if isinstance(value, str) and value in _JSON_WORDS:
        value = _JSON_WORDS[value]
    return key, value


def _ini_unsafe(text: str) -> object:
    """`ini`'s `unsafe()`: a quoted value (single quotes stripped first) through `JSON.parse`;
    otherwise cut at the first unescaped `;` or `#`, with `\\;`, `\\#` and `\\\\` unescaped."""
    text = text.strip(_JS_SPACE)
    if text[:1] in ('"', "'") and text.endswith(text[0]):
        if text[0] == "'":
            text = text[1:-1]
        try:
            return loads_bounded(text)
        except ValueError:  # also `TooDeep`: a deeply nested array names no setting either
            return text
    out: list[str] = []
    escaped = False
    for ch in text:
        if escaped:
            out.append(ch if ch in "\\;#" else "\\" + ch)
            escaped = False
        elif ch in ";#":
            break
        elif ch == "\\":
            escaped = True
        else:
            out.append(ch)
    if escaped:
        out.append("\\")
    return "".join(out).strip(_JS_SPACE)


def _safe_verify(value: object) -> bool:
    """`false`, or a string `error`, `warn` or `false` with no expansion."""
    if value is False:
        return True
    return isinstance(value, str) and "${" not in value and value.casefold() in SAFE_VERIFY_DEPS


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
