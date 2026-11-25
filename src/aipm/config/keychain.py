"""API keys from the OS keychain (ADR-0033, SECURITY.md §8).

Keys come from the environment first; an empty value counts as unset. The keychain is the
fallback, under `service="aipm", account=<variable name>`, and only for the names `prime()` is
given: the user config's `llm.api_key_env` and the shipped adapters' `required_env`
(`AGENT_KEY_NAMES`), never a `pass_env` name or a name from a repository.

Every value is read once per process, by `prime()`, before any redactor is built, and kept here,
never in `os.environ`: so every redactor (`observability.redaction`) knows it, and gates, scanners
and prepare steps, whose environments are built from `os.environ`, never get it.

On macOS the Keychain is reached through `/usr/bin/security`, run by `run_safe` with a timeout
and a constructed environment whose `HOME` comes from the password database, so a repository
`.env` cannot point it at another keychain. No keyring backend selection takes part, so
`PYTHON_KEYRING_BACKEND`, `KEYRING_PROPERTY_*`, `keyringrc.cfg` and `keyring.backends` entry
points change nothing. aipm stores a key with `security` itself, so the item's access list trusts
`security` and a lookup never raises the authorization dialog; a lookup that fails for any
reason (no item, a locked keychain, a timeout) counts as unset. The key reaches `security` on
stdin, never in argv.

On Linux, Secret Service is reached over the D-Bus session bus, which a sandboxed gate may also
reach, so the keychain is not used there until the sandbox is shown to block it (ADR-0033): keys
come from the environment only.
"""

import re
import sys
from collections.abc import Iterable, Mapping
from pathlib import Path
from typing import Protocol

from aipm.config import locations
from aipm.domain.errors import AipmError
from aipm.execution.process import build_env, run_safe

SERVICE = "aipm"
"""The keychain service every aipm key is stored under."""

AGENT_KEY_NAMES: tuple[str, ...] = (
    "ANTHROPIC_API_KEY",
    "CODEX_API_KEY",
    "GEMINI_API_KEY",
    "COPILOT_GITHUB_TOKEN",
)
"""Every shipped adapter's `required_env` (a test keeps the two lists equal)."""

SECURITY_TOOL = "/usr/bin/security"
LOOKUP_TIMEOUT_S = 5.0
_NAME = re.compile(r"[A-Za-z_][A-Za-z0-9_]{0,99}")
KEY_VALUE = re.compile(r"[A-Za-z0-9._~+/=:\-]{8,4096}")
"""What aipm accepts as an API key: the characters keys use, so a key never needs quoting."""


class Backend(Protocol):
    """A keychain: one secret per account name under `SERVICE`."""

    label: str

    def get(self, account: str) -> str | None:
        """The stored value, or `None` when there is none or it cannot be read without a prompt."""
        ...

    def store(self, account: str, value: str) -> None:
        """Store `value`, replacing any earlier one. Raises `OSError` on failure."""
        ...


class MacKeychain:
    """The login keychain, through `/usr/bin/security` (no keyring backend selection)."""

    label = "macOS Keychain"

    def _run(self, argv: list[str], stdin: bytes | None = None) -> tuple[int, str]:
        home = locations.account_home()
        if home is None:
            return -1, ""
        result = run_safe(
            argv,
            cwd=Path("/"),
            env=build_env((), extra={"HOME": home, "PATH": "/usr/bin:/bin", "LANG": "C"}),
            timeout_s=LOOKUP_TIMEOUT_S,
            stdin=stdin,
            max_output_bytes=8192,
        )
        if result.timed_out or result.truncated:
            return -1, ""
        code = -1 if result.returncode is None else result.returncode
        return code, result.stdout.decode("utf-8", errors="replace")

    def get(self, account: str) -> str | None:
        argv = [SECURITY_TOOL, "find-generic-password", "-s", SERVICE, "-a", account, "-w"]
        code, out = self._run(argv)
        if code != 0:
            return None
        return out.removesuffix("\n")

    def store(self, account: str, value: str) -> None:
        if not _NAME.fullmatch(account) or not KEY_VALUE.fullmatch(value):
            raise OSError("refusing to store a key with unexpected characters")
        # `security -i` reads its commands from stdin, so the key never appears in argv. The old
        # item is deleted first: `-U` alone would keep an access list someone else set.
        command = (
            f"delete-generic-password -a {account} -s {SERVICE}\n"
            f'add-generic-password -a {account} -s {SERVICE} -w "{value}"\n'
        )
        code, _ = self._run([SECURITY_TOOL, "-i"], stdin=command.encode("ascii"))
        if code != 0 or self.get(account) != value:
            raise OSError("the macOS Keychain did not store the key")


_override: Backend | None = None
_override_set = False
_cache: dict[str, str] = {}


def platform_backend() -> Backend | None:
    """The keychain aipm uses on this platform, or `None` where it uses none."""
    if _override_set:
        return _override
    if sys.platform == "darwin" and Path(SECURITY_TOOL).is_file():
        return MacKeychain()
    return None


def use_backend(backend: Backend | None) -> None:
    """Test seam: replace the platform backend (`None` = no keychain) and forget cached values."""
    global _override, _override_set
    _override, _override_set = backend, True
    _cache.clear()


def reset() -> None:
    """Test seam: back to the platform backend, with nothing cached."""
    global _override, _override_set
    _override, _override_set = None, False
    _cache.clear()


def _read(backend: Backend, account: str) -> str | None:
    """One lookup; any failure, or a value that is not a plausible key, counts as unset."""
    try:
        value = backend.get(account)
    except (AipmError, OSError):
        return None
    if value is None or not KEY_VALUE.fullmatch(value):
        return None
    return value


def prime(names: Iterable[str], environ: Mapping[str, str]) -> list[str]:
    """Read each named key from the keychain once and keep it; return warnings to show.

    Warns when the environment and the keychain both hold a value and they differ, because a
    repository `.env` loaded into the shell can override the key.
    """
    backend = platform_backend()
    warnings: list[str] = []
    if backend is None:
        return warnings
    for name in dict.fromkeys(names):
        if not _NAME.fullmatch(name) or name in _cache:
            continue
        value = _read(backend, name)
        if value is None:
            continue
        _cache[name] = value
        if environ.get(name) and environ[name] != value:
            warnings.append(
                f"{name} is set in the environment and differs from the key in the "
                f"{backend.label}; aipm uses the environment's"
            )
    return warnings


def resolve(name: str, environ: Mapping[str, str]) -> tuple[str | None, str | None]:
    """The key for `name` and where it came from: `"environment"`, `"keychain"` or nowhere."""
    if environ.get(name):
        return environ[name], "environment"
    if name in _cache:
        return _cache[name], "keychain"
    return None, None


def resolved_values() -> dict[str, str]:
    """Every value read from the keychain, by variable name, for the redactors."""
    return dict(_cache)


def store(name: str, value: str) -> str:
    """Store a key (only `aipm setup` calls this); returns the keychain's label.

    Raises `OSError` when this platform has no keychain aipm uses, or the keychain refuses.
    """
    backend = platform_backend()
    if backend is None:
        raise OSError("aipm uses no keychain on this platform")
    if not _NAME.fullmatch(name):
        raise OSError(f"{name!r} is not a variable name")
    backend.store(name, value)
    _cache[name] = value
    return backend.label


def describe() -> str:
    """One line for `aipm doctor`."""
    backend = platform_backend()
    if backend is not None:
        return backend.label
    return "not used on this platform (keys come from the environment; ADR-0033)"
