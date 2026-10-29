"""Layered config: defaults < user < repo < env < flags, with key classes enforced (§15).

The user layer, `AIPM_*` variables and CLI flags are the user's own (T0) and may set anything.
The repo layer (`.pm/config.yaml`) is limited by key class: a user-only key is ignored, and a
tighten-only key can only make the value stricter than the layers below it. Each ignored key,
and each tighten-only value that ends up looser than the built-in default, becomes a warning
that the CLI prints on every run.
"""

import os
from collections.abc import Mapping
from dataclasses import dataclass
from importlib.resources import files
from pathlib import Path
from typing import Any, get_args, get_origin

import platformdirs
from pydantic import BaseModel, ValidationError

from aipm.config.schema import Config, KeyClass, Tighten, key_class, stricter
from aipm.domain.errors import SchemaError
from aipm.domain.models import SCHEMA_VERSION, ArtifactKind
from aipm.state.store import open_store
from aipm.state.yamlio import MAX_YAML_BYTES, load_yaml

USER_CONFIG_ENV = "AIPM_CONFIG"
_ENV_ALIASES: Mapping[str, tuple[str, ...]] = {"AIPM_LOG_LEVEL": ("logging", "level")}
REPO_SOURCE = ".pm/config.yaml"


@dataclass(frozen=True, slots=True)
class LoadedConfig:
    """The effective configuration, the warnings to print, and the files that were read."""

    config: Config
    warnings: tuple[str, ...]
    sources: tuple[str, ...]


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
    current: M, layer: BaseModel, *, path: str, repo: bool, warnings: list[str]
) -> M:
    """Apply the explicitly set fields of `layer` on top of `current`."""
    updates: dict[str, Any] = {}
    fields = type(layer).model_fields
    for name in (n for n in fields if n in layer.model_fields_set):
        field = fields[name]
        key = f"{path}{field.alias or name}"
        new, old = getattr(layer, name), getattr(current, name)
        if _model_type(field.annotation) is not None:
            updates[name] = _merge(old, new, path=f"{key}.", repo=repo, warnings=warnings)
            continue
        item_model = _dict_of_models(field.annotation)
        if item_model is not None:
            merged = dict(old)
            for item_key, item in new.items():
                base = merged.get(item_key, item_model())
                label = f"{key}.{getattr(item_key, 'value', item_key)}."
                merged[item_key] = _merge(base, item, path=label, repo=repo, warnings=warnings)
            updates[name] = merged
            continue
        rule = key_class(field.metadata)
        if repo and rule is KeyClass.USER_ONLY:
            warnings.append(f"{REPO_SOURCE}: ignored {key}: it is a user-only key")
            continue
        if repo and isinstance(rule, Tighten):
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


def _read_user_layer(path: Path) -> object:
    try:
        with path.open("rb") as handle:
            data = handle.read(MAX_YAML_BYTES + 1)
    except FileNotFoundError:
        return {}
    except OSError as exc:
        raise SchemaError(f"cannot read user config {path} ({exc.strerror})") from None
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError:
        raise SchemaError(f"user config {path} is not valid UTF-8") from None
    return load_yaml(text, source=str(path))


def load_config(
    project: Path | None,
    *,
    env: Mapping[str, str] | None = None,
    flags: Mapping[str, object] | None = None,
) -> LoadedConfig:
    """Merge every layer; ignore user-only repo keys and repo relaxations, with warnings.

    `project` is the repository root (None outside a repository). `flags` maps dotted keys,
    such as `dispatch.default_tool`, to values given on the command line.
    """
    environ = os.environ if env is None else env
    warnings: list[str] = []
    sources: list[str] = []
    config = defaults()

    user_path = user_config_path(environ)
    user_raw = _read_user_layer(user_path)
    if user_raw != {}:
        sources.append(str(user_path))
    config = _merge(config, _validate(user_raw, str(user_path)), path="", repo=False, warnings=[])

    if project is not None:
        repo_text = open_store(project).read_text(ArtifactKind.CONFIG)
        if repo_text is not None:
            sources.append(REPO_SOURCE)
            repo_layer = _validate(load_yaml(repo_text, source=REPO_SOURCE), REPO_SOURCE)
            config = _merge(config, repo_layer, path="", repo=True, warnings=warnings)

    env_layer = _env_layer(environ)
    if env_layer:
        sources.append("environment")
        config = _merge(
            config,
            _validate(env_layer, "AIPM_* environment variables"),
            path="",
            repo=False,
            warnings=[],
        )

    if flags:
        flag_layer = _nested(
            {tuple(key.split(".")): value for key, value in flags.items()}, "flags"
        )
        config = _merge(
            config, _validate(flag_layer, "command-line flags"), path="", repo=False, warnings=[]
        )

    final = _validate(config.model_dump(mode="json", by_alias=True), "the merged configuration")
    warnings.extend(f"relaxed: {item}" for item in relaxations(final))
    return LoadedConfig(config=final, warnings=tuple(warnings), sources=tuple(sources))
