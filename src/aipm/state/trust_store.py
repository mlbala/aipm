"""The user-level trust store (C-21, SECURITY.md §6), outside the repository.

The execution surface is everything aipm would run or hand to an agent: the prepare and gate
argv (each checked by the command policy, each executable resolved with `shutil.which`), the
allowed argv prefixes, dispatch flags, the sandbox and network settings, config-defined
scanners and every tighten-only relaxation. Its hash is sha256 of canonical JSON, so any change
to any of these, or to where an executable resolves on PATH, needs trust again.

`trust.json` lives in `platformdirs.user_state_dir("aipm")`, is written atomically with mode
0600, and is refused if another user could have written it. `--yes` never writes here.
"""

import hashlib
import json
import os
import secrets
import shlex
import shutil
import stat
from collections.abc import Callable, Mapping
from contextlib import suppress
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Protocol

import platformdirs
from pydantic import AwareDatetime, Field, ValidationError

from aipm import __version__
from aipm.config.loader import relaxations
from aipm.config.schema import Config
from aipm.domain.errors import AipmError, PolicyViolation
from aipm.domain.models import GateDef, PrepareDef, RepoId, StrictModel
from aipm.domain.models.base import Sha256, Str200, Str500
from aipm.security.command_policy import CommandPolicy, check_argv, compile_gate, compile_prepare

SURFACE_VERSION = 1
TRUST_FILE = "trust.json"
MAX_TRUST_BYTES = 4 * 1_048_576
_POLICY_REPORT = Path("/aipm-report-file")  # stands in for {report_file} in policy checks

type Which = Callable[[str], str | None]


class TrustStore(Protocol):
    """Per-user, per-machine approval of a repository's execution surface."""

    def surface_hash(self, cfg: Config) -> str:
        """Return the canonical hash of the execution surface."""
        ...

    def is_trusted(self, repo: RepoId, surface_hash: str) -> bool:
        """Return whether this exact surface was trusted for the repository."""
        ...

    def trust(self, repo: RepoId, surface_hash: str, summary: str) -> None:
        """Record trust (only after interactive confirmation or `--confirm`)."""
        ...


class TrustEntry(StrictModel):
    """One trusted repository."""

    surface_hash: Sha256
    trusted_at: AwareDatetime
    aipm_version: Str200
    summary: Str500 = ""


class TrustFile(StrictModel):
    """The whole of `trust.json`."""

    version: int = Field(default=1, ge=1, le=1)
    repos: dict[str, TrustEntry] = Field(default_factory=dict[str, TrustEntry], max_length=10_000)


def _checked[T](stage: str, check: Callable[[], T]) -> T:
    try:
        return check()
    except AipmError as exc:
        raise PolicyViolation(
            f"{stage} is not allowed by the command policy: {exc.message}",
            hint="Fix .pm/config.yaml or your user config; such a surface can never be trusted.",
        ) from None


class _LazyPolicy:
    """Builds the command policy on first use, so a surface without argv needs no prefixes."""

    def __init__(self, cfg: Config) -> None:
        self._cfg = cfg
        self._policy: CommandPolicy | None = None

    def __call__(self) -> CommandPolicy:
        if self._policy is None:
            self._policy = _checked("the allowed argv prefixes", self._cfg.command_policy)
        return self._policy


def _gate_entry(name: str, gate: GateDef, policy: _LazyPolicy, which: Which) -> dict[str, Any]:
    if gate.run is None:
        return {
            "builtin": None if gate.builtin is None else gate.builtin.value,
            "required": gate.required,
            "fail_on": None if gate.fail_on is None else gate.fail_on.value,
            "mode": gate.mode,
        }
    _checked(
        f"gate {name!r}",
        lambda: compile_gate(gate, paths=[], policy=policy(), report_file=_POLICY_REPORT),
    )
    return {"argv": list(gate.run), "resolved": which(gate.run[0]), "required": gate.required}


def _prepare_entry(step: PrepareDef, policy: _LazyPolicy, which: Which) -> dict[str, Any]:
    _checked("the prepare step", lambda: compile_prepare(step, policy=policy()))
    return {"argv": list(step.run), "resolved": which(step.run[0]), "network": step.network.value}


def _scanner_entry(
    name: str, run: tuple[str, ...], policy: _LazyPolicy, which: Which
) -> dict[str, Any]:
    _checked(f"scanner {name!r}", lambda: check_argv(run, policy(), stage="gate"))
    return {"argv": list(run), "resolved": which(run[0])}


def execution_surface(cfg: Config, *, which: Which = shutil.which) -> dict[str, Any]:
    """The canonical execution surface (SECURITY.md §6).

    Raises `PolicyViolation` (exit 6) if any configured argv or prefix fails the command policy.
    """
    policy = _LazyPolicy(cfg)
    prefixes = [*cfg.allowed_executables, *cfg.security.extra_allowed_executables]
    if prefixes:
        policy()
    prepare = None if cfg.prepare is None else _prepare_entry(cfg.prepare, policy, which)
    return {
        "version": SURFACE_VERSION,
        "allowed_executables": [list(p) for p in cfg.allowed_executables],
        "extra_allowed_executables": [list(p) for p in cfg.security.extra_allowed_executables],
        "resolved_executables": {p[0]: which(p[0]) for p in sorted(prefixes)},
        "prepare": prepare,
        "gates": {
            name: _gate_entry(name, gate, policy, which) for name, gate in sorted(cfg.gates.items())
        },
        "scanners_extra": {
            name: _scanner_entry(name, scanner.run, policy, which)
            for name, scanner in sorted(cfg.scanners.extra.items())
        },
        "dispatch": {
            "enabled": cfg.dispatch.enabled,
            "default_tool": cfg.dispatch.default_tool.value,
            "sandbox": cfg.dispatch.sandbox.value,
            "tools": {
                tool.value: settings.model_dump(mode="json")
                for tool, settings in sorted(cfg.dispatch.tools.items())
            },
        },
        "require_sandbox": cfg.security.require_sandbox,
        "network": cfg.security.network.model_dump(mode="json"),
        "relaxations": relaxations(cfg),
    }


def canonical_json(value: object) -> str:
    """Sorted keys, no whitespace, ASCII only: one byte string per surface."""
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def hash_surface(surface: Mapping[str, Any]) -> str:
    """`surface_hash = sha256(canonical_json(surface))` (SECURITY.md §6 rule 1)."""
    return hashlib.sha256(canonical_json(surface).encode("ascii")).hexdigest()


def render_surface(surface: Mapping[str, Any], surface_hash: str) -> list[str]:
    """Every argv and flag in full, without truncation, plus the hash (for `aipm trust`)."""

    def argv_line(entry: Mapping[str, Any]) -> str:
        resolved = entry.get("resolved") or "not found on PATH"
        return f"{shlex.join(entry['argv'])}    [{resolved}]"

    lines = ["Execution surface", ""]
    prepare = surface["prepare"]
    lines.append("prepare:")
    lines.append(f"  {argv_line(prepare)}  network={prepare['network']}" if prepare else "  (none)")
    lines.append("gates:")
    if not surface["gates"]:
        lines.append("  (none)")
    for name, gate in surface["gates"].items():
        required = "required" if gate["required"] else "optional"
        if "argv" in gate:
            lines.append(f"  {name} ({required}): {argv_line(gate)}")
        else:
            extra = "".join(
                f" {key}={gate[key]}" for key in ("fail_on", "mode") if gate.get(key) is not None
            )
            lines.append(f"  {name} ({required}): built-in {gate['builtin']}{extra}")
    for title, key in (
        ("allowed argv prefixes", "allowed_executables"),
        ("user-level extra prefixes", "extra_allowed_executables"),
    ):
        lines.append(f"{title}:")
        lines.extend(f"  {shlex.join(prefix)}" for prefix in surface[key])
        if not surface[key]:
            lines.append("  (none)")
    for name, scanner in surface["scanners_extra"].items():
        lines.append(f"scanner {name}: {argv_line(scanner)}")
    dispatch = surface["dispatch"]
    lines.append(
        f"dispatch: enabled={dispatch['enabled']} default_tool={dispatch['default_tool']} "
        f"sandbox={dispatch['sandbox']} require_sandbox={surface['require_sandbox']}"
    )
    for tool, settings in dispatch["tools"].items():
        lines.append(
            f"  {tool}: bare={settings['bare']} allow_auto_mode={settings['allow_auto_mode']} "
            f"pass_env={settings['pass_env']}"
        )
    network = surface["network"]
    lines.append(
        f"network: agent={network['agent']} gates={network['gates']} prepare={network['prepare']}"
    )
    lines.append("relaxations:")
    lines.extend(f"  {item}" for item in surface["relaxations"])
    if not surface["relaxations"]:
        lines.append("  (none)")
    lines.extend(["", f"surface hash: {surface_hash}", f"confirm with: {surface_hash[:12]}"])
    return lines


def default_trust_path() -> Path:
    """`<user_state_dir>/aipm/trust.json`."""
    return Path(platformdirs.user_state_dir("aipm", appauthor=False)) / TRUST_FILE


class FileTrustStore:
    """`TrustStore` over one JSON file in the user's state directory."""

    def __init__(self, path: Path, *, which: Which = shutil.which) -> None:
        self.path = path
        self._which = which

    def surface(self, cfg: Config) -> dict[str, Any]:
        """The execution surface for `cfg`, resolved against the current PATH."""
        return execution_surface(cfg, which=self._which)

    def surface_hash(self, cfg: Config) -> str:
        """Return the canonical hash of the execution surface."""
        return hash_surface(self.surface(cfg))

    def _load(self) -> TrustFile:
        try:
            fd = os.open(self.path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        except FileNotFoundError:
            return TrustFile()
        except OSError as exc:
            message = f"cannot read the trust store {self.path} ({exc.strerror})"
            raise PolicyViolation(message) from None
        with os.fdopen(fd, "rb") as handle:
            info = os.fstat(handle.fileno())
            unsafe = info.st_uid != os.getuid() or info.st_mode & 0o022
            if not stat.S_ISREG(info.st_mode) or unsafe:
                raise PolicyViolation(
                    f"the trust store {self.path} is not a private file of yours",
                    hint="Remove it and trust your repositories again.",
                )
            data = handle.read(MAX_TRUST_BYTES + 1)
        try:
            if len(data) > MAX_TRUST_BYTES:
                raise ValueError("too large")
            return TrustFile.model_validate_json(data)
        except (ValidationError, ValueError):
            raise PolicyViolation(
                f"the trust store {self.path} is damaged",
                hint="Remove it and trust your repositories again.",
            ) from None

    def _save(self, content: TrustFile) -> None:
        directory = self.path.parent
        directory.mkdir(mode=0o700, parents=True, exist_ok=True)
        tmp = directory / f"{TRUST_FILE}.tmp-{os.getpid()}-{secrets.token_hex(4)}"
        payload = content.model_dump_json(indent=2).encode("utf-8") + b"\n"
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        try:
            with os.fdopen(fd, "wb") as handle:
                handle.write(payload)
                handle.flush()
                os.fsync(handle.fileno())
            tmp.replace(self.path)
        except BaseException:
            with suppress(FileNotFoundError):
                tmp.unlink()
            raise
        dir_fd = os.open(directory, os.O_RDONLY)
        try:
            os.fsync(dir_fd)
        finally:
            os.close(dir_fd)

    def entry(self, repo: RepoId) -> TrustEntry | None:
        """The trust record of a repository, if any."""
        return self._load().repos.get(repo)

    def is_trusted(self, repo: RepoId, surface_hash: str) -> bool:
        """Return whether this exact surface was trusted for the repository."""
        found = self.entry(repo)
        return found is not None and secrets.compare_digest(found.surface_hash, surface_hash)

    def trust(self, repo: RepoId, surface_hash: str, summary: str) -> None:
        """Record trust (only after interactive confirmation or `--confirm`)."""
        content = self._load()
        content.repos[repo] = TrustEntry(
            surface_hash=surface_hash,
            trusted_at=datetime.now(UTC),
            aipm_version=__version__[:200],
            summary=summary[:500],
        )
        self._save(content)

    def revoke(self, repo: RepoId) -> bool:
        """Remove trust for a repository; returns whether there was any."""
        content = self._load()
        if content.repos.pop(repo, None) is None:
            return False
        self._save(content)
        return True


def default_trust_store() -> FileTrustStore:
    """Return the store at `<user_state_dir>/aipm/trust.json` (mode 0600)."""
    return FileTrustStore(default_trust_path())
