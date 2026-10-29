"""Logging redaction and terminal output safety (SECURITY.md §7.10, §8; invariants I-5, I-6).

The redactors used by `StateStore` and logging are built from the full `os.environ` (the LLM
gateway's arrives with build prompt 03): a secret set in any environment variable with a
secret-like name never reaches a log line or a `.pm/` file.
"""

import io
import json
import logging
import os
import stat
from collections.abc import Iterator
from pathlib import Path

import pytest

from aipm.app.runtime import user_redactor
from aipm.cli.output import print_untrusted
from aipm.domain.models import PrdDoc, PrdFrontMatter
from aipm.observability.logging import LOGGER_NAME, configure_logging
from aipm.state.store import open_store
from tests.conftest import FakeSecrets
from tests.fakes.secrets import FAKE_SECRETS

# A registered fake secret, set under a name the fake_secrets fixture does not use.
LATE_SECRET = FAKE_SECRETS["AIPM_TEST_DB_PASSWORD"]


@pytest.fixture
def logs(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Iterator[tuple[io.StringIO, Path]]:
    """Logging configured into a temp dir, with stderr captured."""
    stderr = io.StringIO()
    monkeypatch.setattr("sys.stderr", stderr)
    path = configure_logging("debug", json_lines=False, stderr_level="debug", directory=tmp_path)
    assert path is not None
    yield stderr, path
    for handler in list(logging.getLogger(LOGGER_NAME).handlers):
        logging.getLogger(LOGGER_NAME).removeHandler(handler)
        handler.close()


def test_store_redactor_is_built_from_the_full_environment(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("SOME_LATE_TOKEN", LATE_SECRET)
    store = open_store(tmp_path)
    assert store.redactor.env_names == frozenset(os.environ)
    meta = PrdFrontMatter.model_validate({"derived_from": {"requirements": "a" * 64}})
    store.save(PrdDoc(meta=meta, body=f"leak {LATE_SECRET}\n"))
    assert LATE_SECRET not in (store.root / "prd.md").read_text(encoding="utf-8")


def test_logging_redacts_every_handler(
    fake_secrets: FakeSecrets, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    monkeypatch.setenv("SOME_LATE_TOKEN", LATE_SECRET)
    stderr = io.StringIO()
    monkeypatch.setattr("sys.stderr", stderr)
    path = configure_logging("debug", json_lines=False, stderr_level="debug", directory=tmp_path)
    assert path is not None
    logger = logging.getLogger(f"{LOGGER_NAME}.test")
    secrets = [*fake_secrets.values.values(), LATE_SECRET]
    logger.warning("values: %s", " ".join(secrets))
    try:
        raise RuntimeError(f"boom {secrets[0]}")
    except RuntimeError:
        logger.exception("failed")
    for handler in logging.getLogger(LOGGER_NAME).handlers:
        handler.flush()
    file_text = path.read_text(encoding="utf-8")
    for text in (stderr.getvalue(), file_text):
        assert "REDACTED" in text
        for secret in secrets:
            assert secret not in text
    for handler in logging.getLogger(LOGGER_NAME).handlers:
        handler.close()


def test_log_lines_carry_no_terminal_escapes(logs: tuple[io.StringIO, Path]) -> None:
    stderr, path = logs
    logging.getLogger(LOGGER_NAME).warning("title \x1b]52;c;ZXZpbA==\x07 \x1b[2J done")
    for handler in logging.getLogger(LOGGER_NAME).handlers:
        handler.flush()
    assert stderr.getvalue() == "aipm: WARNING: title   done\n"
    entry = json.loads(path.read_text(encoding="utf-8").splitlines()[-1])
    assert entry["message"] == "title   done"
    assert entry["level"] == "warning"


def test_log_file_is_private(logs: tuple[io.StringIO, Path]) -> None:
    _, path = logs
    assert stat.S_IMODE(path.stat().st_mode) == 0o600
    assert stat.S_IMODE(path.parent.stat().st_mode) & 0o077 == 0


def test_json_lines_on_stderr_and_levels(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    stderr = io.StringIO()
    monkeypatch.setattr("sys.stderr", stderr)
    configure_logging("info", json_lines=True, stderr_level="warning", directory=tmp_path)
    logging.getLogger(LOGGER_NAME).info("quiet on the terminal")
    logging.getLogger(LOGGER_NAME).error("loud")
    lines = stderr.getvalue().splitlines()
    assert [json.loads(line)["message"] for line in lines] == ["loud"]


def test_an_unwritable_log_dir_only_disables_the_file(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr("sys.stderr", io.StringIO())
    blocker = tmp_path / "file"
    blocker.write_text("not a directory", encoding="utf-8")
    assert configure_logging("info", json_lines=False, directory=blocker / "logs") is None
    assert len(logging.getLogger(LOGGER_NAME).handlers) == 1


# ---------------------------------------------------------------- print_untrusted


def test_print_untrusted_never_interprets_markup_or_escapes(
    capsys: pytest.CaptureFixture[str],
) -> None:
    hostile = (
        "[bold red]markup[/bold red] :smile: "
        "\x1b]8;;https://evil.example\x1b\\click\x1b]8;;\x1b\\ "
        "\x1b]52;c;ZXZpbA==\x07\x1b[31mred\u202e\u200b\n"
    )
    print_untrusted(hostile)
    out = capsys.readouterr().out
    assert out.startswith("[bold red]markup[/bold red] :smile: click red")
    assert "\x1b" not in out
    assert "\u202e" not in out and "\u200b" not in out


def test_print_untrusted_to_stderr(capsys: pytest.CaptureFixture[str]) -> None:
    print_untrusted("to stderr \x1b[1m", err=True)
    captured = capsys.readouterr()
    assert captured.out == ""
    assert captured.err == "to stderr \n"


def test_cli_logging_applies_the_users_redact_patterns(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    config = tmp_path / "user.yaml"
    config.write_text("security: {extra_redact_patterns: ['ACME-[0-9]{6}']}\n", encoding="utf-8")
    monkeypatch.setenv("AIPM_CONFIG", str(config))
    assert user_redactor().redact("ticket ACME-123456") == "ticket «REDACTED:custom»"
    config.write_text("telemetry: true\n", encoding="utf-8")
    assert user_redactor().redact("ticket ACME-123456") == "ticket ACME-123456"
