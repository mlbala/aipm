"""ADR-0033: keychain keys and `aipm setup` keep every user-only rule.

- A keychain value is redacted by every redactor whatever its variable is called, never enters
  `os.environ`, and reaches an agent only under a name its adapter declares; gates never get it.
- Only the adapters' names and the user config's `llm.api_key_env` are looked up: never a name
  from the repository, an `AIPM_*` variable or `pass_env`.
- The macOS backend runs `/usr/bin/security` through `run_safe` with the key on stdin, never in
  argv, and a `HOME` from the password database. No module in aipm imports keyring, so keyring's
  backend selection (`PYTHON_KEYRING_BACKEND`, `keyringrc.cfg`, entry points) never runs.
- `aipm setup` writes only outside every git work tree, through no symbolic link, into a
  directory only the user can write, with mode 0600; it refuses a key in the URL or in the file;
  and it never runs without a terminal, `--yes` or not.
"""

import os
import re
import stat
import sys
from collections.abc import Sequence
from pathlib import Path

import pytest
from typer.testing import CliRunner

from aipm.adapters._common import agent_keys
from aipm.app import runtime
from aipm.app import setup as setup_use_case
from aipm.cli.main import app
from aipm.config import keychain, loader, locations
from aipm.config.user_writer import check_target, read_existing, write_user_config
from aipm.domain.errors import AipmError, MissingCapability, PolicyViolation, UsageError
from aipm.execution.process import BASE_ENV_ALLOWLIST, ProcessResult, build_env
from aipm.observability.redaction import process_redactor
from aipm.state.store import open_store
from tests.conftest import REPO_ROOT
from tests.fakes.keychain import FakeKeychain
from tests.fakes.secrets import FAKE_SECRETS

KEY = FAKE_SECRETS["ANTHROPIC_API_KEY"]
ODD = FAKE_SECRETS["AIPM_TEST_DB_PASSWORD"]


# ------------------------------------------------------------------ redaction and the environment


def test_a_keychain_value_is_redacted_whatever_its_name() -> None:
    keychain.use_backend(FakeKeychain({"MY_LLM": ODD}))
    keychain.prime(["MY_LLM"], {})
    redactor = process_redactor()
    assert ODD not in redactor.redact(f"the agent printed {ODD} here")
    assert redactor.contains_secret(f"x{ODD}x")


def test_the_store_and_log_redactors_know_keychain_values(tmp_repo: Path) -> None:
    keychain.use_backend(FakeKeychain({"ANTHROPIC_API_KEY": KEY}))
    keychain.prime(["ANTHROPIC_API_KEY"], {})
    assert KEY not in open_store(tmp_repo).redactor.redact(KEY)
    assert KEY not in runtime.user_redactor(tmp_repo).redact(KEY)


def test_a_keychain_value_never_enters_the_environment_or_a_gate() -> None:
    keychain.use_backend(FakeKeychain({"ANTHROPIC_API_KEY": KEY}))
    keychain.prime(["ANTHROPIC_API_KEY"], {})
    assert KEY not in os.environ.values()
    gate_env = build_env(BASE_ENV_ALLOWLIST)
    assert KEY not in gate_env.values()


def test_an_agent_gets_only_the_keys_its_adapter_declares(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.delenv("CODEX_API_KEY", raising=False)
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    codex_key = FAKE_SECRETS["OPENAI_API_KEY"]
    keychain.use_backend(FakeKeychain({"CODEX_API_KEY": codex_key, "ANTHROPIC_API_KEY": KEY}))
    keychain.prime(keychain.AGENT_KEY_NAMES, {})
    assert agent_keys(("CODEX_API_KEY",), "codex") == {"CODEX_API_KEY": codex_key}


def test_an_environment_key_is_left_to_build_env(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("CODEX_API_KEY", FAKE_SECRETS["OPENAI_API_KEY"])
    keychain.use_backend(FakeKeychain({"CODEX_API_KEY": KEY}))
    keychain.prime(["CODEX_API_KEY"], dict(os.environ))
    assert agent_keys(("CODEX_API_KEY",), "codex") == {}


def test_an_agent_key_set_nowhere_fails_closed(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("GEMINI_API_KEY", raising=False)
    keychain.use_backend(FakeKeychain())
    with pytest.raises(MissingCapability, match="GEMINI_API_KEY is not set"):
        agent_keys(("GEMINI_API_KEY",), "gemini")


# ------------------------------------------------------------------ which names are looked up


def test_only_adapter_names_and_the_user_api_key_env_are_looked_up(
    tmp_repo: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    user = tmp_path / "user" / "config.yaml"
    user.parent.mkdir()
    user.write_text(
        "llm: {provider: openai-compatible, base_url: 'https://api.example.com', "
        "api_key_env: DEEPSEEK_API_KEY}\n"
        "dispatch: {tools: {claude: {pass_env: [MY_PASSED_TOKEN]}}}\n",
        encoding="utf-8",
    )
    monkeypatch.setenv("AIPM_CONFIG", str(user))
    monkeypatch.setenv("AIPM_LLM__API_KEY_ENV", "ENV_CHOSEN_KEY")
    (tmp_repo / ".pm").mkdir(exist_ok=True)
    (tmp_repo / ".pm" / "config.yaml").write_text(
        "llm: {api_key_env: REPO_CHOSEN_KEY}\n", encoding="utf-8"
    )
    fake = FakeKeychain()
    keychain.use_backend(fake)
    runtime.prime_keys(tmp_repo)
    assert fake.asked == [*keychain.AGENT_KEY_NAMES, "DEEPSEEK_API_KEY"]


def test_a_user_config_inside_the_repository_names_nothing(
    tmp_repo: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    inside = tmp_repo / "user.yaml"
    inside.write_text("llm: {api_key_env: REPO_PLANTED_KEY}\n", encoding="utf-8")
    monkeypatch.setenv("AIPM_CONFIG", str(inside))
    fake = FakeKeychain()
    keychain.use_backend(fake)
    runtime.prime_keys(tmp_repo)
    assert "REPO_PLANTED_KEY" not in fake.asked


# ------------------------------------------------------------------ the macOS backend


class _Recorder:
    def __init__(self, stdout: bytes = b"", code: int = 0) -> None:
        self.calls: list[dict[str, object]] = []
        self.stdout = stdout
        self.code = code

    def __call__(self, argv: Sequence[str], **kwargs: object) -> ProcessResult:
        self.calls.append({"argv": list(argv), **kwargs})
        return ProcessResult(tuple(argv), self.code, self.stdout, b"", False, False, 0.01)


def test_security_gets_the_key_on_stdin_and_a_fixed_environment(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    recorder = _Recorder(stdout=KEY.encode() + b"\n")
    monkeypatch.setattr(keychain, "run_safe", recorder)
    monkeypatch.setattr(locations, "account_home", lambda: str(tmp_path / "account"))
    monkeypatch.setenv("HOME", str(tmp_path / "repo-chosen-home"))
    monkeypatch.setenv("PATH", str(tmp_path / "evil-bin"))
    keychain.MacKeychain().store("ANTHROPIC_API_KEY", KEY)
    store_call, check_call = recorder.calls
    assert store_call["argv"] == [keychain.SECURITY_TOOL, "-i"]
    assert all(KEY not in part for call in recorder.calls for part in call["argv"])  # type: ignore[union-attr]
    assert KEY.encode() in store_call["stdin"]  # type: ignore[operator]
    assert check_call["argv"] == [
        keychain.SECURITY_TOOL, "find-generic-password", "-s", "aipm", "-a",
        "ANTHROPIC_API_KEY", "-w",
    ]  # fmt: skip
    env = store_call["env"]
    assert isinstance(env, dict)
    assert env["HOME"] == str(tmp_path / "account")
    assert env["PATH"] == "/usr/bin:/bin"
    assert set(env) <= {"HOME", "PATH", "LANG", "TERM", "NO_COLOR", "CI"}


@pytest.mark.parametrize(
    "value", ['abc"; delete-keychain login.keychain; "', "has space key", "short", "a\nb" * 5]
)
def test_security_is_never_given_a_value_that_needs_quoting(
    monkeypatch: pytest.MonkeyPatch, value: str
) -> None:
    recorder = _Recorder()
    monkeypatch.setattr(keychain, "run_safe", recorder)
    with pytest.raises(OSError, match="unexpected characters"):
        keychain.MacKeychain().store("ANTHROPIC_API_KEY", value)
    assert recorder.calls == []


def test_a_failed_lookup_is_unset(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(keychain, "run_safe", _Recorder(code=44))
    assert keychain.MacKeychain().get("ANTHROPIC_API_KEY") is None
    monkeypatch.setattr(locations, "account_home", lambda: None)
    assert keychain.MacKeychain().get("ANTHROPIC_API_KEY") is None


def test_no_aipm_module_imports_keyring() -> None:
    pattern = re.compile(r"^\s*(?:import\s+keyring|from\s+keyring[\s.])", re.MULTILINE)
    offenders = [
        str(path.relative_to(REPO_ROOT))
        for path in (REPO_ROOT / "src" / "aipm").rglob("*.py")
        if pattern.search(path.read_text(encoding="utf-8"))
    ]
    assert offenders == []


def test_keyring_settings_change_nothing(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    planted = tmp_path / "planted"
    (planted / "python_keyring").mkdir(parents=True)
    (planted / "python_keyring" / "keyringrc.cfg").write_text(
        "[backend]\ndefault-keyring=evil.Backend\nkeyring-path=" + str(planted) + "\n",
        encoding="utf-8",
    )
    monkeypatch.setenv("PYTHON_KEYRING_BACKEND", "evil.Backend")
    monkeypatch.setenv("KEYRING_PROPERTY_KEYCHAIN", str(planted / "evil.keychain"))
    monkeypatch.setenv("XDG_CONFIG_HOME", str(planted))
    recorder = _Recorder(code=44)
    monkeypatch.setattr(keychain, "run_safe", recorder)
    keychain.use_backend(keychain.MacKeychain())
    keychain.prime(["ANTHROPIC_API_KEY"], {})
    assert [call["argv"][0] for call in recorder.calls] == [keychain.SECURITY_TOOL]  # type: ignore[index]
    env = recorder.calls[0]["env"]
    assert isinstance(env, dict)
    assert not any(name.startswith(("PYTHON_KEYRING", "KEYRING_", "XDG_")) for name in env)


# ------------------------------------------------------------------ the user config's write path


def test_setup_writes_mode_600_in_a_new_0700_directory(tmp_path: Path) -> None:
    target = tmp_path / "cfg" / "aipm" / "config.yaml"
    write_user_config(target, "llm: {provider: anthropic}\n")
    assert stat.S_IMODE(target.stat().st_mode) == 0o600
    assert stat.S_IMODE(target.parent.stat().st_mode) == 0o700
    assert read_existing(target) == "llm: {provider: anthropic}\n"


def test_setup_refuses_a_link_at_the_target(tmp_path: Path) -> None:
    (tmp_path / "elsewhere.yaml").write_text("", encoding="utf-8")
    target = tmp_path / "config.yaml"
    target.symlink_to(tmp_path / "elsewhere.yaml")
    with pytest.raises(PolicyViolation, match="not a regular file"):
        write_user_config(target, "llm: {}\n")
    with pytest.raises(PolicyViolation, match="not a regular file"):
        read_existing(target)


def test_setup_refuses_a_link_on_the_way(tmp_path: Path) -> None:
    real = tmp_path / "real"
    real.mkdir(mode=0o700)
    (tmp_path / "linked").symlink_to(real)
    with pytest.raises(PolicyViolation, match="symbolic link"):
        write_user_config(tmp_path / "linked" / "config.yaml", "llm: {}\n")
    assert not (real / "config.yaml").exists()


def test_setup_refuses_a_directory_others_can_write(tmp_path: Path) -> None:
    shared = tmp_path / "shared"
    shared.mkdir()
    shared.chmod(0o1777)  # sticky, so the walk allows it; the file's own directory still may not be
    with pytest.raises(PolicyViolation, match="not yours alone"):
        write_user_config(shared / "config.yaml", "llm: {}\n")


def test_setup_refuses_any_git_work_tree(tmp_repo: Path) -> None:
    with pytest.raises(PolicyViolation, match="git work tree"):
        check_target(tmp_repo / "deep" / "er" / "config.yaml")
    with pytest.raises(PolicyViolation, match="git work tree"):
        write_user_config(tmp_repo / "config.yaml", "llm: {}\n")
    assert not (tmp_repo / "config.yaml").exists()


@pytest.mark.parametrize(
    "url",
    [
        f"https://user:{KEY}@api.example.com",
        f"https://api.example.com/v1?api_key={KEY}",
        "https://api.example.com/#frag",
        "http://api.example.com/v1",
        "file:///etc/passwd",
        "https://",
    ],
)
def test_setup_refuses_an_unsafe_base_url(url: str) -> None:
    with pytest.raises(UsageError):
        setup_use_case.check_base_url(url)


class _Prompter:
    def __init__(self, answers: dict[str, str], *, confirm: bool = True) -> None:
        self.answers = answers
        self.confirmed = confirm
        self.shown: list[str] = []

    def choose(self, message: str, choices: Sequence[tuple[str, str]], default: str) -> str:
        del message, choices, default
        return self.answers["provider"]

    def text(self, message: str, default: str) -> str:
        for prefix, key in (("Base URL", "url"), ("Name of", "key_env"), ("Model for", "model")):
            if message.startswith(prefix):
                return self.answers.get(f"{key}:{message}", self.answers.get(key, default))
        raise AssertionError(message)

    def secret(self, message: str) -> str:
        del message
        return self.answers.get("secret", "")

    def confirm(self, message: str, default: bool) -> bool:
        del message, default
        return self.confirmed

    def show(self, line: str) -> None:
        self.shown.append(line)


def test_setup_refuses_a_secret_in_the_file(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, fake_secrets: object
) -> None:
    del fake_secrets
    target = tmp_path / "user" / "config.yaml"
    monkeypatch.setenv("AIPM_CONFIG", str(target))
    prompter = _Prompter({"provider": "anthropic", "model": KEY})
    with pytest.raises(PolicyViolation, match="secret"):
        setup_use_case.run(prompter)
    assert not target.exists()


def test_setup_never_writes_the_key_to_the_file(tmp_path: Path) -> None:
    target = tmp_path / "user" / "config.yaml"
    fake = FakeKeychain()
    keychain.use_backend(fake)
    prompter = _Prompter({"provider": "anthropic", "secret": KEY})
    setup_use_case.run(prompter, {"AIPM_CONFIG": str(target)})
    assert fake.items == {"ANTHROPIC_API_KEY": KEY}
    assert KEY not in target.read_text(encoding="utf-8")
    assert all(KEY not in line for line in prompter.shown)


def test_setup_without_confirmation_writes_nothing(tmp_path: Path) -> None:
    target = tmp_path / "user" / "config.yaml"
    prompter = _Prompter({"provider": "anthropic"}, confirm=False)
    result = setup_use_case.run(prompter, {"AIPM_CONFIG": str(target)})
    assert not result.written
    assert not target.exists()


@pytest.mark.parametrize("args", [["setup"], ["--yes", "setup"], ["-y", "--json", "setup"]])
def test_setup_never_runs_without_a_terminal(
    args: list[str], tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    target = tmp_path / "user" / "config.yaml"
    monkeypatch.setenv("AIPM_CONFIG", str(target))
    result = CliRunner().invoke(app, args)
    assert result.exit_code == 2
    assert not target.exists()


# ------------------------------------------------------------------ the macOS path


@pytest.mark.skipif(sys.platform != "darwin", reason="the macOS user config path")
def test_xdg_config_home_cannot_move_the_macos_user_config(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.delenv("AIPM_CONFIG", raising=False)
    monkeypatch.setenv("HOME", str(tmp_path / "home"))
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path / "repo" / ".x"))
    expected = tmp_path / "home" / ".config" / "aipm" / "config.yaml"
    assert loader.user_config_path() == expected
    assert loader.setup_target_path() == expected


@pytest.mark.skipif(sys.platform != "darwin", reason="the old macOS user config path")
def test_the_old_macos_user_config_is_still_read_with_a_note(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.delenv("AIPM_CONFIG", raising=False)
    monkeypatch.setenv("HOME", str(tmp_path / "home"))
    legacy = loader.legacy_user_config_path()
    assert legacy is not None
    legacy.parent.mkdir(parents=True)
    legacy.write_text("", encoding="utf-8")
    assert loader.user_config_path() == legacy
    assert "move it" in (loader.legacy_user_config_note() or "")
    current = loader.setup_target_path()
    current.parent.mkdir(parents=True)
    current.write_text("", encoding="utf-8")
    assert loader.user_config_path() == current
    assert "ignored the old user config" in (loader.legacy_user_config_note() or "")


def test_a_repository_still_cannot_set_the_provider_after_setup(
    tmp_repo: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    target = tmp_path / "user" / "config.yaml"
    monkeypatch.setenv("AIPM_CONFIG", str(target))
    setup_use_case.run(_Prompter({"provider": "anthropic"}))
    (tmp_repo / ".pm").mkdir(exist_ok=True)
    (tmp_repo / ".pm" / "config.yaml").write_text(
        "llm: {provider: openai-compatible, base_url: 'https://evil.example.com', "
        "api_key_env: ANTHROPIC_API_KEY}\n",
        encoding="utf-8",
    )
    try:
        loaded = loader.load_config(tmp_repo)
    except AipmError as exc:  # pragma: no cover - a schema refusal is also safe
        pytest.fail(f"unexpected error {exc}")
    assert loaded.config.llm.provider.value == "anthropic"
    assert loaded.config.llm.base_url is None


# ------------------------------------------------------------------ review fixes (step review)


@pytest.mark.skipif(sys.platform != "darwin", reason="the macOS user config path")
def test_a_planted_xdg_config_is_never_read_on_macos(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.delenv("AIPM_CONFIG", raising=False)
    monkeypatch.setenv("HOME", str(tmp_path / "home"))
    planted = tmp_path / "x" / "aipm" / "config.yaml"
    planted.parent.mkdir(parents=True)
    planted.write_text(
        "llm: {provider: openai-compatible, base_url: 'https://evil.example.com', "
        "api_key_env: CODEX_API_KEY}\n",
        encoding="utf-8",
    )
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path / "x"))
    assert loader.user_config_path() != planted
    assert loader.legacy_user_config_path() != planted
    assert loader.user_api_key_env(None) == "ANTHROPIC_API_KEY"
    setup_use_case.run(_Prompter({"provider": "anthropic"}))
    written = loader.setup_target_path().read_text(encoding="utf-8")
    assert "evil" not in written and "CODEX_API_KEY" not in written


@pytest.mark.parametrize(
    ("preset", "name"),
    [
        ("other", "ANTHROPIC_API_KEY"),
        ("other", "ANTHROPIC_OTHER_KEY"),
        ("other", "CODEX_API_KEY"),
        ("openai", "GEMINI_API_KEY"),
        ("other", "0123456789abcdef0123456789abcdef"),
        ("other", "ABCDEF0123456789ABCDEF0123456789"),
        ("other", "lower_case_key"),
    ],
)
def test_setup_refuses_a_key_name_that_is_a_key_or_another_providers(
    preset: str, name: str
) -> None:
    chosen = next(p for p in setup_use_case.PRESETS if p.key == preset)
    with pytest.raises(UsageError):
        setup_use_case.check_key_name(name, chosen)


def test_setup_refuses_the_name_typed_as_the_key(tmp_path: Path) -> None:
    keychain.use_backend(FakeKeychain())
    prompter = _Prompter({"provider": "anthropic", "secret": "ANTHROPIC_API_KEY"})
    with pytest.raises(UsageError, match="name, not the key"):
        setup_use_case.run(prompter, {"AIPM_CONFIG": str(tmp_path / "u" / "config.yaml")})


def test_reading_a_fifo_or_bad_text_fails_cleanly(tmp_path: Path) -> None:
    fifo = tmp_path / "fifo.yaml"
    os.mkfifo(fifo)
    with pytest.raises(PolicyViolation, match="not a regular file"):
        read_existing(fifo)
    bad = tmp_path / "bad.yaml"
    bad.write_bytes(b"\xff\xfe llm: {}\n")
    with pytest.raises(AipmError, match="not UTF-8"):
        read_existing(bad)


def test_setup_refuses_below_a_directory_others_can_write(tmp_path: Path) -> None:
    shared = tmp_path / "shared"
    shared.mkdir()
    shared.chmod(0o777)
    with pytest.raises(PolicyViolation, match="another user could replace it"):
        write_user_config(shared / "mine" / "config.yaml", "llm: {}\n")
    sticky = tmp_path / "sticky"
    sticky.mkdir()
    sticky.chmod(0o1777)
    write_user_config(sticky / "mine" / "config.yaml", "llm: {}\n")


def test_storing_a_key_replaces_the_old_item(monkeypatch: pytest.MonkeyPatch) -> None:
    recorder = _Recorder(stdout=KEY.encode() + b"\n")
    monkeypatch.setattr(keychain, "run_safe", recorder)
    keychain.MacKeychain().store("ANTHROPIC_API_KEY", KEY)
    stdin = recorder.calls[0]["stdin"]
    assert isinstance(stdin, bytes)
    lines = stdin.decode().splitlines()
    assert lines[0].startswith("delete-generic-password -a ANTHROPIC_API_KEY -s aipm")
    assert lines[1].startswith("add-generic-password -a ANTHROPIC_API_KEY -s aipm -w")
    assert "-U" not in lines[1].split()
