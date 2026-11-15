"""Layered config: defaults < user < repo < env < flags, with key classes enforced (§15).

The user layer and CLI flags are the user's own (T0) and may set anything. The repo layer
(`.pm/config.yaml`) is limited by key class: a user-only key is ignored, and a tighten-only key
can only make the value stricter than the layers below it.

Tools such as pipenv load a repository's `.env` into the environment, so the environment is not
always the user's own (ADR-0018, SECURITY.md §6 rule 5):

- an `AIPM_*` variable that sets a user-only key is refused (exit 6), never applied;
- an `AIPM_*` variable may relax a tighten-only key, with a warning naming the key;
- the user config file, wherever `AIPM_CONFIG`, `HOME` or `XDG_CONFIG_HOME` puts it, must be an
  absolute path outside the repository (compared by inode, so firmlinks and case variants count)
  and a regular file (exit 6 otherwise);
- a missing user config is an empty one at the default location, but exit 6 when `AIPM_CONFIG`
  names it (v0.1 O-2).

Each ignored key, and each tighten-only value that ends up looser than the built-in default,
becomes a warning that the CLI prints on every run.
"""

import os
import stat
from collections.abc import Mapping
from dataclasses import dataclass
from importlib.resources import files
from pathlib import Path
from typing import Any, get_args, get_origin

import platformdirs
from pydantic import BaseModel, ValidationError

from aipm.config.locations import USER_CONFIG_ENV, git_root
from aipm.config.schema import Config, KeyClass, Tighten, key_class, stricter
from aipm.domain.errors import PolicyViolation, SchemaError
from aipm.domain.models import SCHEMA_VERSION, ArtifactKind, NetworkProfile
from aipm.security.paths import is_within
from aipm.state.store import open_store
from aipm.state.yamlio import MAX_YAML_BYTES, load_yaml

_ENV_ALIASES: Mapping[str, tuple[str, ...]] = {"AIPM_LOG_LEVEL": ("logging", "level")}
REPO_SOURCE = ".pm/config.yaml"
ENV_SOURCE = "AIPM_* environment variables"


@dataclass(frozen=True, slots=True)
class _Limits:
    """How key classes limit one layer.

    `user_only` is what a user-only key gets: `allow`, `ignore` (with a warning) or `refuse`
    (exit 6). `tighten_only` keeps a tighten-only key at least as strict as before, and
    `warn_relaxed` lets it relax but says so.
    """

    source: str = ""
    user_only: str = "allow"
    tighten_only: bool = False
    warn_relaxed: bool = False


_OWN = _Limits()
_REPO = _Limits(REPO_SOURCE, user_only="ignore", tighten_only=True)
_ENV = _Limits(ENV_SOURCE, user_only="refuse", warn_relaxed=True)


@dataclass(frozen=True, slots=True)
class LoadedConfig:
    """The effective configuration, the warnings to print, and the files that were read."""

    config: Config
    warnings: tuple[str, ...]
    sources: tuple[str, ...]
    unflagged: Config | None = None
    """The configuration before the command-line layer, from the same read of every file; `None`
    when no flag was given (then it is `config`)."""

    def without_flags(self) -> "LoadedConfig":
        """This configuration without the command-line layer. Trust is checked on it, so the
        surface checked and the one that runs come from one read of `.pm/config.yaml` (red-team
        v0.4, RT04-7)."""
        if self.unflagged is None:
            return self
        return LoadedConfig(config=self.unflagged, warnings=self.warnings, sources=self.sources)


def user_config_path(env: Mapping[str, str] | None = None) -> Path:
    """`$AIPM_CONFIG`, else `<user_config_dir>/aipm/config.yaml`."""
    override = (os.environ if env is None else env).get(USER_CONFIG_ENV)
    if override:
        return Path(override).expanduser()
    return Path(platformdirs.user_config_dir("aipm", appauthor=False)) / "config.yaml"


def _describe(exc: ValidationError, source: str) -> str:
    parts = [
        f"{'.'.join(str(p) for p in error['loc']) or '(document)'}: {error['msg']}"
        for error in exc.errors()[:5]
    ]
    more = exc.error_count() - len(parts)
    return f"{source} is not valid: " + "; ".join(parts) + (f"; and {more} more" if more else "")


def _validate(raw: object, source: str) -> Config:
    """Validate one layer on its own (every key is optional)."""
    if raw is None:
        raw = {}
    if not isinstance(raw, dict):
        raise SchemaError(f"{source} must be a YAML mapping")
    layer: dict[str, Any] = raw  # pyright: ignore[reportUnknownVariableType]
    version = layer.get("schema_version")
    if isinstance(version, int) and not isinstance(version, bool) and version > SCHEMA_VERSION:
        raise SchemaError(
            f"{source} has schema_version {version}; this aipm reads up to {SCHEMA_VERSION}",
            hint="Upgrade aipm to read this file.",
        )
    try:
        return Config.model_validate(layer)
    except ValidationError as exc:
        raise SchemaError(_describe(exc, source), hint=f"Fix {source}.") from None


def defaults() -> Config:
    """The built-in defaults from `aipm/config/defaults.yaml`."""
    text = (files("aipm.config") / "defaults.yaml").read_text(encoding="utf-8")
    return _validate(load_yaml(text, source="defaults.yaml"), "aipm's defaults.yaml")


def _model_type(annotation: object) -> type[BaseModel] | None:
    return (
        annotation if isinstance(annotation, type) and issubclass(annotation, BaseModel) else None
    )


def _has_key_classes(model: type[BaseModel]) -> bool:
    for field in model.model_fields.values():
        nested = _model_type(field.annotation)
        if key_class(field.metadata) is not KeyClass.REPO_OK:
            return True
        if nested is not None and _has_key_classes(nested):
            return True
    return False


def _dict_of_models(annotation: object) -> type[BaseModel] | None:
    """The value model of a `dict[K, Model]` field whose model carries key classes."""
    if get_origin(annotation) is not dict:
        return None
    value = _model_type(get_args(annotation)[1])
    return value if value is not None and _has_key_classes(value) else None


def _show(value: object) -> str:
    if isinstance(value, list):
        items: list[object] = value  # pyright: ignore[reportUnknownVariableType]
        return "[" + ", ".join(_show(item) for item in items) + "]"
    return str(getattr(value, "value", value))


def _merge[M: BaseModel](
    current: M, layer: BaseModel, *, path: str, limits: _Limits, warnings: list[str]
) -> M:
    """Apply the explicitly set fields of `layer` on top of `current`."""
    updates: dict[str, Any] = {}
    fields = type(layer).model_fields
    for name in (n for n in fields if n in layer.model_fields_set):
        field = fields[name]
        key = f"{path}{field.alias or name}"
        new, old = getattr(layer, name), getattr(current, name)
        if _model_type(field.annotation) is not None:
            updates[name] = _merge(old, new, path=f"{key}.", limits=limits, warnings=warnings)
            continue
        item_model = _dict_of_models(field.annotation)
        if item_model is not None:
            merged = dict(old)
            for item_key, item in new.items():
                base = merged.get(item_key, item_model())
                label = f"{key}.{getattr(item_key, 'value', item_key)}."
                merged[item_key] = _merge(base, item, path=label, limits=limits, warnings=warnings)
            updates[name] = merged
            continue
        rule = key_class(field.metadata)
        if rule is KeyClass.USER_ONLY and limits.user_only == "refuse":
            raise PolicyViolation(
                f"{limits.source} set the user-only key {key}; aipm refuses to run, because a "
                "repository .env file loaded by a tool such as pipenv can fill the environment",
                hint=f"Unset the AIPM_* variable and set {key} in your user config, or pass it "
                "as a command-line flag.",
            )
        if rule is KeyClass.USER_ONLY and limits.user_only == "ignore":
            warnings.append(f"{limits.source}: ignored {key}: it is a user-only key")
            continue
        if limits.warn_relaxed and isinstance(rule, Tighten) and stricter(rule, old, new) != new:
            warnings.append(f"{limits.source}: relaxed {key} to {_show(new)} (was {_show(old)})")
        if limits.tighten_only and isinstance(rule, Tighten):
            tightened = stricter(rule, old, new)
            if tightened != new:
                warnings.append(
                    f"{REPO_SOURCE}: {key} cannot be relaxed by the repository; "
                    f"kept {_show(tightened)}"
                )
            new = tightened
        updates[name] = new
    return current.model_copy(update=updates)


def relaxations(config: Config, base: Config | None = None) -> list[str]:
    """Tighten-only values looser than the built-in defaults (part of the execution surface)."""
    found: list[str] = []
    _relaxed(config, base if base is not None else defaults(), "", found)
    return found


def _relaxed(current: BaseModel, base: BaseModel, path: str, found: list[str]) -> None:
    for name, field in type(current).model_fields.items():
        key = f"{path}{field.alias or name}"
        value, default = getattr(current, name), getattr(base, name)
        if _model_type(field.annotation) is not None:
            _relaxed(value, default, f"{key}.", found)
            continue
        item_model = _dict_of_models(field.annotation)
        if item_model is not None:
            for item_key, item in value.items():
                label = f"{key}.{getattr(item_key, 'value', item_key)}."
                _relaxed(item, default.get(item_key, item_model()), label, found)
            continue
        rule = key_class(field.metadata)
        if isinstance(rule, Tighten) and stricter(rule, default, value) != value:
            found.append(f"{key} is relaxed to {_show(value)} (default {_show(default)})")


def _nested(items: Mapping[tuple[str, ...], object], source: str) -> dict[str, Any]:
    layer: dict[str, Any] = {}
    for path, value in items.items():
        node: dict[str, Any] = layer
        for part in path[:-1]:
            child: Any = node.setdefault(part, {})
            if not isinstance(child, dict):
                raise SchemaError(f"{source}: {'.'.join(path)} conflicts with another setting")
            node = child  # pyright: ignore[reportUnknownVariableType]
        if path[-1] in node:
            raise SchemaError(f"{source}: {'.'.join(path)} conflicts with another setting")
        node[path[-1]] = value
    return layer


def _env_value(raw: str) -> object:
    try:
        parsed = load_yaml(raw, source="environment")
    except SchemaError:
        return raw
    return raw if parsed is None else parsed


def _env_layer(env: Mapping[str, str]) -> dict[str, Any]:
    """`AIPM_LOG_LEVEL`, and `AIPM_<SECTION>__<KEY>` for nested keys (`__` separates levels)."""
    items: dict[tuple[str, ...], object] = {}
    for name, raw in sorted(env.items()):
        if not name.startswith("AIPM_") or not raw.strip():
            continue
        if name in _ENV_ALIASES:
            path = _ENV_ALIASES[name]
        elif "__" in name:
            path = tuple(part.lower() for part in name.removeprefix("AIPM_").split("__"))
        else:
            continue
        items[path] = _env_value(raw)
    return _nested(items, "environment")


def _check_user_path(path: Path, project: Path | None) -> None:
    """The user config must be absolute and outside the repository (ADR-0018).

    The path comes from `AIPM_CONFIG`, `HOME` or `XDG_CONFIG_HOME`, all of which a repository
    `.env` can set. Without a project (`aipm init`, the CLI redactor) the repository around the
    current directory counts.
    """
    if not path.is_absolute():
        raise PolicyViolation(
            f"the user config path must be absolute, not {str(path)[:200]!r}",
            hint="A relative path is read from the current directory, which may be a "
            "repository. Point AIPM_CONFIG at an absolute path, or `~/...`.",
        )
    root = project if project is not None else git_root(Path.cwd())
    if root is not None and is_within(path, root):
        raise PolicyViolation(
            f"the user config {str(path)[:200]} is inside the repository; a repository can "
            "never be your user config",
            hint="Keep your user config outside the repository. Check AIPM_CONFIG, HOME and "
            "XDG_CONFIG_HOME, which a repository .env loaded by a tool such as pipenv can set.",
        )


def _explicit(env: Mapping[str, str]) -> bool:
    """Whether `AIPM_CONFIG` names the user config (an empty value means the default)."""
    return bool(env.get(USER_CONFIG_ENV))


def _read_user_layer(path: Path, *, explicit: bool) -> object:
    """Read the user config: a regular file (links followed), never a FIFO or a device.

    A missing file at the default location is an empty config (a new user has none). A missing
    file that `AIPM_CONFIG` names is refused (exit 6): running without the settings the user
    pointed at, such as a stricter network profile, would be a silent fallback (v0.1 O-2).
    """
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NONBLOCK)
    except FileNotFoundError:
        if not explicit:
            return {}
        raise PolicyViolation(
            f"{USER_CONFIG_ENV} names {str(path)[:200]}, which does not exist",
            hint=f"Create the file (it may be empty), or unset {USER_CONFIG_ENV} to use "
            f"{user_config_path({})}. aipm does not run without the user config you named.",
        ) from None
    except OSError as exc:
        raise SchemaError(f"cannot read user config {path} ({exc.strerror})") from None
    mode = os.fstat(fd).st_mode
    if not stat.S_ISREG(mode):
        os.close(fd)
        if stat.S_ISDIR(mode):
            raise SchemaError(f"cannot read user config {path} (it is a directory)")
        raise PolicyViolation(f"the user config {str(path)[:200]} is not a regular file")
    with os.fdopen(fd, "rb") as handle:
        data = handle.read(MAX_YAML_BYTES + 1)
    if len(data) > MAX_YAML_BYTES:
        raise SchemaError(f"user config {path} is larger than 1 MiB")
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError:
        raise SchemaError(f"user config {path} is not valid UTF-8") from None
    return load_yaml(text, source=str(path))


def _user_layer(path: Path, project: Path | None, *, explicit: bool) -> Config:
    _check_user_path(path, project)
    return _validate(_read_user_layer(path, explicit=explicit), str(path))


def user_redact_patterns(
    project: Path | None = None, *, env: Mapping[str, str] | None = None
) -> list[str]:
    """`security.extra_redact_patterns` from the user config file only.

    Patterns from the repository or the environment are never used: a regex that backtracks
    without end would hang every redaction, and one that matches aipm's own sentences would erase
    them from prompts (red-team v0.1 review).
    """
    environ = os.environ if env is None else env
    path = user_config_path(environ)
    layer = _user_layer(path, project, explicit=_explicit(environ))
    return list(layer.security.extra_redact_patterns)


def _check_open_network(final: Config, user: Config) -> None:
    """`open` is honoured only from the user config file (SECURITY.md §9.1).

    A repository cannot relax a tighten-only key, but an `AIPM_*` variable can, and a repository
    `.env` can fill the environment (R-8), so that route is refused for this one value.
    """
    for name in type(final.security.network).model_fields:
        if getattr(final.security.network, name) is not NetworkProfile.OPEN:
            continue
        if getattr(user.security.network, name) is not NetworkProfile.OPEN:
            raise PolicyViolation(
                f"security.network.{name} is open, but your user config does not set it",
                hint=f"Set security.network.{name}: open in your user config, or use another "
                "profile. A repository or an AIPM_* variable cannot open the network.",
            )


def load_config(
    project: Path | None,
    *,
    env: Mapping[str, str] | None = None,
    flags: Mapping[str, object] | None = None,
    read_repo: bool = True,
) -> LoadedConfig:
    """Merge every layer; ignore repo relaxations and user-only repo keys, with warnings.

    Exit 6 when the environment sets a user-only key, when the user config is relative or
    inside the repository, or when `AIPM_CONFIG` names a file that does not exist.

    `project` is the repository root (None outside a repository). `flags` maps dotted keys,
    such as `dispatch.default_tool`, to values given on the command line. With `read_repo`
    false, the user config is still checked against `project`, but `.pm/config.yaml` is not
    read (`aipm init --force` rewrites it, so a broken one must not stop the repair).
    """
    environ = os.environ if env is None else env
    warnings: list[str] = []
    sources: list[str] = []
    config = defaults()

    user_path = user_config_path(environ)
    _check_user_path(user_path, project)
    user_raw = _read_user_layer(user_path, explicit=_explicit(environ))
    if user_raw != {}:
        sources.append(str(user_path))
    user_layer = _validate(user_raw, str(user_path))
    config = _merge(config, user_layer, path="", limits=_OWN, warnings=[])

    if project is not None and read_repo:
        repo_text = open_store(project).read_text(ArtifactKind.CONFIG)
        if repo_text is not None:
            sources.append(REPO_SOURCE)
            repo_layer = _validate(load_yaml(repo_text, source=REPO_SOURCE), REPO_SOURCE)
            config = _merge(config, repo_layer, path="", limits=_REPO, warnings=warnings)

    env_layer = _env_layer(environ)
    if env_layer:
        sources.append("environment")
        config = _merge(
            config, _validate(env_layer, ENV_SOURCE), path="", limits=_ENV, warnings=warnings
        )

    unflagged: Config | None = None
    if flags:
        unflagged = _validate(config.model_dump(mode="json", by_alias=True), "the configuration")
        _check_open_network(unflagged, user_layer)
        flag_layer = _nested(
            {tuple(key.split(".")): value for key, value in flags.items()}, "flags"
        )
        config = _merge(
            config, _validate(flag_layer, "command-line flags"), path="", limits=_OWN, warnings=[]
        )

    final = _validate(config.model_dump(mode="json", by_alias=True), "the merged configuration")
    _check_open_network(final, user_layer)
    warnings.extend(f"relaxed: {item}" for item in relaxations(final))
    return LoadedConfig(
        config=final, warnings=tuple(warnings), sources=tuple(sources), unflagged=unflagged
    )
