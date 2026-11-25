"""`aipm setup`: write the user config, and optionally store the key in the keychain (ADR-0033).

Setup asks for the provider, the models and the key-variable name, shows the exact file and the
`llm:` block it will write, and writes only after an interactive yes (`--yes` never skips it).
It changes only `llm.provider`, `llm.base_url`, `llm.api_key_env` and `llm.models`; the rest of an
existing file is kept as data (comments are not). The key, if given, goes to the OS keychain and
never into a file. A repository cannot reach any of this: setup is interactive only, and the
file it writes must lie outside every git work tree.
"""

import ipaddress
import os
import re
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Protocol, cast

from aipm.config import keychain, locations
from aipm.config.loader import (
    legacy_user_config_path,
    parse_user_config,
    setup_target_path,
    user_config_path,
)
from aipm.config.locations import USER_CONFIG_ENV
from aipm.config.schema import Provider
from aipm.config.user_writer import check_target, read_existing, write_user_config
from aipm.domain.errors import PolicyViolation, UsageError
from aipm.observability.redaction import process_redactor
from aipm.state.yamlio import dump_yaml

README_SECTION = "README.md, 'Set up your model provider and API keys'"
_DEFAULT_MODELS = {
    "default": "claude-sonnet-5-5",
    "interviewer": "claude-haiku-5-5",
    "ac_reviewer": "claude-haiku-5-5",
}
_MODEL_ROLES = ("default", "interviewer", "ac_reviewer")


@dataclass(frozen=True, slots=True)
class Preset:
    """One provider choice."""

    key: str
    title: str
    provider: Provider
    base_url: str | None
    key_env: str
    ask_url: bool = False
    ask_key_env: bool = False
    needs_key: bool = True
    models: Mapping[str, str] = field(default_factory=dict[str, str])


PRESETS: tuple[Preset, ...] = (
    Preset("anthropic", "Anthropic (Claude)", Provider.ANTHROPIC, None, "ANTHROPIC_API_KEY",
           models=_DEFAULT_MODELS),
    Preset("openai", "OpenAI", Provider.OPENAI_COMPATIBLE, None, "OPENAI_API_KEY"),
    Preset("other", "Another OpenAI-compatible service (DeepSeek, OpenRouter, Azure, vLLM ...)",
           Provider.OPENAI_COMPATIBLE, None, "LLM_API_KEY", ask_url=True, ask_key_env=True),
    Preset("ollama", "A local Ollama server (no key)", Provider.OPENAI_COMPATIBLE,
           "http://localhost:11434/v1", "OLLAMA_API_KEY", ask_url=True, needs_key=False),
)  # fmt: skip


class SetupPrompter(Protocol):
    """The questions setup asks; the CLI implements them with questionary."""

    def choose(self, message: str, choices: Sequence[tuple[str, str]], default: str) -> str: ...

    def text(self, message: str, default: str) -> str: ...

    def secret(self, message: str) -> str: ...

    def confirm(self, message: str, default: bool) -> bool: ...

    def show(self, line: str) -> None: ...


@dataclass(frozen=True, slots=True)
class SetupResult:
    """What setup did, as JSON-ready data."""

    path: str
    written: bool
    keychain: str | None
    data: dict[str, object]


_URL = re.compile(
    r"(?P<scheme>https?)://(?P<host>\[[0-9A-Fa-f:.]+\]|[A-Za-z0-9.\-]+)(?::(?P<port>[0-9]{1,5}))?"
    r"(?P<path>/[A-Za-z0-9._~!$&'()*+,;=:@%/\-]*)?"
)


def check_base_url(url: str) -> str:
    """An `https` URL, or `http` to a loopback address only, with no user info, query or
    fragment, so a key pasted into the URL prompt is refused."""
    text = url.strip()
    if len(text) > 300:
        raise UsageError("the URL is too long")
    authority = text.split("/", 3)[2] if text.count("/") >= 2 else text
    if "@" in authority:
        raise UsageError("the URL must not contain a user name or password")
    if "?" in text or "#" in text:
        raise UsageError("the URL must not contain a query (?…) or fragment (#…)")
    match = _URL.fullmatch(text)
    if match is None:
        raise UsageError("the URL must look like https://host[:port][/path]")
    host = match["host"].strip("[]")
    if match["scheme"] == "http" and not _loopback(host):
        raise UsageError("http:// is allowed only for a server on this machine; use https://")
    return text


_KEY_NAME = re.compile(r"[A-Z][A-Z0-9]*(?:_[A-Z0-9]+)+")


def check_key_name(name: str, preset: Preset) -> None:
    """A variable name, not a key pasted at the wrong prompt, and never another provider's.

    The name must look like `SOME_API_KEY` (upper case, at least one `_`), so a key typed here is
    refused rather than written to the file. An OpenAI-compatible provider may not use an
    `ANTHROPIC_*` name or a coding agent's key name: setup would store this provider's key over
    that one, and the agent would send it to its own provider.
    """
    if not _KEY_NAME.fullmatch(name) or len(name) > 100:
        raise UsageError(
            "the variable name must look like DEEPSEEK_API_KEY (capitals, digits and _); "
            "type the key itself later, when setup asks for it"
        )
    if preset.provider is Provider.OPENAI_COMPATIBLE and (
        name.startswith("ANTHROPIC_") or name in keychain.AGENT_KEY_NAMES
    ):
        raise UsageError(f"{name} belongs to another provider or a coding agent; use its own name")


def _loopback(host: str) -> bool:
    if host.lower() == "localhost":
        return True
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


def _chosen_by(environ: Mapping[str, str]) -> str | None:
    if environ.get(USER_CONFIG_ENV):
        return USER_CONFIG_ENV
    home = environ.get("HOME")
    if home and locations.account_home() not in {None, home}:
        return "HOME"
    return None


def _existing(target: Path, environ: Mapping[str, str]) -> tuple[Path | None, dict[str, Any]]:
    """The file setup starts from: the target, or the old macOS file when only that exists."""
    source = target
    legacy = legacy_user_config_path()
    if legacy is not None and user_config_path(environ) == legacy:
        source = legacy
    text = read_existing(source)
    if text is None:
        return None, {}
    data, _ = parse_user_config(text, str(source))
    return source, data


def _ask_models(prompter: SetupPrompter, current: Mapping[str, str]) -> dict[str, str]:
    models: dict[str, str] = {}
    for role in _MODEL_ROLES:
        answer = prompter.text(f"Model for {role}:", current.get(role, "")).strip()
        if answer:
            models[role] = answer
    if "default" not in models:
        raise UsageError("a default model is required")
    return models


def run(prompter: SetupPrompter, environ: Mapping[str, str] | None = None) -> SetupResult:
    """Ask, show, confirm, write; then offer to store the key in the keychain."""
    env = os.environ if environ is None else environ
    target = setup_target_path(env)
    check_target(target)
    source, data = _existing(target, env)
    llm_now: object = data.get("llm")
    llm: dict[str, Any] = dict(cast(dict[str, Any], llm_now)) if isinstance(llm_now, dict) else {}

    preset_key = prompter.choose(
        "Which model provider?", [(p.title, p.key) for p in PRESETS], _guess(llm)
    )
    preset = next(p for p in PRESETS if p.key == preset_key)
    base_url = preset.base_url
    if preset.ask_url:
        default_url = str(llm.get("base_url") or preset.base_url or "https://")
        base_url = check_base_url(prompter.text("Base URL of the API:", default_url))
    key_env = preset.key_env
    if preset.ask_key_env:
        key_env = prompter.text(
            "Name of the environment variable that holds the key (the name, not the key):",
            str(llm.get("api_key_env") or preset.key_env),
        ).strip()
    check_key_name(key_env, preset)
    current_models = llm.get("models") if isinstance(llm.get("models"), dict) else None
    same_provider = _guess(llm) == preset.key
    defaults = dict(current_models) if current_models and same_provider else dict(preset.models)
    models = _ask_models(prompter, defaults)

    llm["provider"] = preset.provider.value
    llm["api_key_env"] = key_env
    llm["models"] = models
    if base_url is None:
        llm.pop("base_url", None)
    else:
        llm["base_url"] = base_url
    data["llm"] = llm
    text = dump_yaml(data)
    _, _validated = parse_user_config(text, "the new user config")
    if process_redactor().contains_secret(text):
        raise PolicyViolation("the new user config looks like it contains a secret; not written")

    prompter.show(f"User config: {target}")
    chosen = _chosen_by(env)
    if chosen is not None:
        prompter.show(f"  (this path comes from {chosen})")
    if source is not None and source != target:
        prompter.show(f"  (read from the old path {source}; you can delete it afterwards)")
    prompter.show("It will contain:")
    for line in text.splitlines():
        prompter.show(f"  {line}")
    if source is not None:
        prompter.show("Other settings in the file are kept; comments are not.")
    if not prompter.confirm("Write this file?", True):
        return SetupResult(str(target), False, None, {"path": str(target), "written": False})
    write_user_config(target, text)
    prompter.show(f"Wrote {target} (mode 600). Check it with `aipm doctor`.")

    stored = _offer_keychain(prompter, preset, key_env, env)
    return SetupResult(
        str(target),
        True,
        stored,
        {"path": str(target), "written": True, "provider": preset.provider.value,
         "api_key_env": key_env, "models": models, "keychain": stored},
    )  # fmt: skip


def _guess(llm: Mapping[str, Any]) -> str:
    if llm.get("provider") in {None, Provider.ANTHROPIC.value}:
        return "anthropic"
    url = str(llm.get("base_url") or "")
    if not url:
        return "openai"
    if "11434" in url:
        return "ollama"
    return "other"


def _offer_keychain(
    prompter: SetupPrompter, preset: Preset, key_env: str, env: Mapping[str, str]
) -> str | None:
    if not preset.needs_key:
        return None
    backend = keychain.platform_backend()
    if backend is None:
        prompter.show(
            f"Now set {key_env} in your shell before running aipm (see {README_SECTION})."
        )
        return None
    key = prompter.secret(
        f"Paste the API key to store in the {backend.label} (input hidden; Enter to skip):"
    ).strip()
    if not key:
        prompter.show(f"Skipped. aipm will read {key_env} from your environment.")
        return None
    if key == key_env:
        raise UsageError("that is the variable's name, not the key")
    if not keychain.KEY_VALUE.fullmatch(key):
        raise UsageError("that does not look like an API key (unexpected characters or length)")
    try:
        label = keychain.store(key_env, key)
    except OSError as exc:
        raise UsageError(f"could not store the key: {exc}") from exc
    prompter.show(f"Stored {key_env} in the {label} (service 'aipm').")
    if env.get(key_env):
        prompter.show(
            f"Note: {key_env} is also set in your environment, and the environment wins. Remove "
            "it from your shell profile to use the keychain."
        )
    return label
