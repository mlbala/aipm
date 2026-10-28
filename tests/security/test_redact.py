"""Secret redaction (SECURITY.md §8, invariant I-5).

The token-shaped values below are built at run time from pieces, so no complete token appears
in the source for secret scanners to flag. None of them is a real credential.
"""

import base64
import logging
import os
import sys

import pytest

from aipm.domain.errors import ExitCode, UsageError
from aipm.observability.redaction import process_redactor
from aipm.security.redact import Redactor
from tests.conftest import FakeSecrets
from tests.fakes.secrets import FAKE_SECRETS

FILLER = "Zq9" * 20  # long, token-alphabet filler


def token(prefix: str, length: int = 40, alphabet: str = FILLER) -> str:
    return prefix + alphabet[:length]


TOKENS = {
    "anthropic_key": token("sk-" + "ant-api03-"),
    "openai_key": token("sk-" + "proj-"),
    "github_token": token("gh" + "p_", 36),
    "github_pat": token("github" + "_pat_", 40),
    "slack_token": token("xo" + "xb-", 24),
    "aws_access_key": "AK" + "IA" + "Q" * 16,
    "google_api_key": "AI" + "za" + "x" * 35,
    "jwt": "ey" + "JhbGciOiJIUzI1NiJ9.ey" + "JzdWIiOiIxMjM0NTY3ODkwIn0.abcdefghijk",
}


@pytest.fixture
def redactor() -> Redactor:
    return Redactor(dict(FAKE_SECRETS))


# ---------------------------------------------------------------- environment values


def test_redacts_environment_secret_values(redactor: Redactor) -> None:
    value = FAKE_SECRETS["ANTHROPIC_API_KEY"]
    out = redactor.redact(f"key is {value}, again {value}.")
    assert value not in out
    assert out == (
        "key is «REDACTED:env:ANTHROPIC_API_KEY», again «REDACTED:env:ANTHROPIC_API_KEY»."
    )


def test_every_fake_secret_is_redacted(redactor: Redactor, fake_secrets: FakeSecrets) -> None:
    text = " | ".join(FAKE_SECRETS.values())
    fake_secrets.assert_absent(redactor.redact(text))


@pytest.mark.parametrize(
    "name",
    ["MY_API_KEY", "github_token", "DB_PASSWORD", "AWS_SECRET_ACCESS_KEY", "GCP_CREDENTIALS"],
)
def test_secret_name_patterns(name: str) -> None:
    redactor = Redactor({name: "value-long-enough"})
    assert redactor.redact("x value-long-enough y") == f"x «REDACTED:env:{name}» y"


def test_ignores_short_values_and_other_names() -> None:
    redactor = Redactor({"API_KEY": "short", "HOME": "/home/someone-long", "EMPTY_TOKEN": ""})
    text = "short /home/someone-long"
    assert redactor.redact(text) == text


def test_longest_value_wins_when_values_overlap() -> None:
    redactor = Redactor({"A_TOKEN": "abcdefgh", "B_TOKEN": "abcdefgh-and-more"})
    assert redactor.redact("abcdefgh-and-more") == "«REDACTED:env:B_TOKEN»"


def test_odd_environment_names_get_a_plain_kind() -> None:
    redactor = Redactor({"weird name»KEY": "value-long-enough"})
    assert redactor.redact("value-long-enough") == "«REDACTED:env»"


def test_keeps_the_names_of_its_snapshot() -> None:
    assert Redactor({"A": "1", "B_KEY": "2"}).env_names == frozenset({"A", "B_KEY"})


# ---------------------------------------------------------------- token formats


@pytest.mark.parametrize(("kind", "value"), sorted(TOKENS.items()))
def test_redacts_known_token_formats(kind: str, value: str) -> None:
    out = Redactor({}).redact(f"found {value} here")
    assert value not in out
    assert out == f"found «REDACTED:{kind}» here"


def test_redacts_bearer_tokens() -> None:
    out = Redactor({}).redact("Authorization: Bearer abcdefghijklmnop.qrs")
    assert out == "Authorization: «REDACTED:bearer»"


def test_redacts_pem_private_keys() -> None:
    pem = (
        "-----BEGIN RSA PRIVATE " + "KEY-----\nMIIBOgIBAAJBAK\nmore\n-----END RSA PRIVATE KEY-----"
    )
    out = Redactor({}).redact(f"before\n{pem}\nafter")
    assert out == "before\n«REDACTED:pem_private_key»\nafter"


def test_redacts_an_unterminated_pem_block_to_the_end() -> None:
    out = Redactor({}).redact("x\n-----BEGIN PRIVATE " + "KEY-----\nMIIBOgIBAAJBAK\nrest")
    assert out == "x\n«REDACTED:pem_private_key»"


def test_token_prefixes_inside_words_are_left_alone() -> None:
    text = "risk-assessment-procedure-details and xghp_notatoken and ask-anthropic-kindly-today"
    assert Redactor({}).redact(text) == text


@pytest.mark.parametrize(
    ("text", "expected"),
    [
        ("api_key = 'abcdefgh1234'", "api_key = '«REDACTED:generic»'"),
        ("API-KEY: abcdefgh1234", "API-KEY: «REDACTED:generic»"),
        ("password=hunter2hunter2", "password=«REDACTED:generic»"),
        ("passwd: abcdefgh", "passwd: «REDACTED:generic»"),
        ('secret = "abcdefgh1234"', 'secret = "«REDACTED:generic»"'),
        ("token: short", "token: short"),
    ],
)
def test_generic_assignment_pattern(text: str, expected: str) -> None:
    assert Redactor({}).redact(text) == expected


def test_markers_are_not_redacted_again(redactor: Redactor) -> None:
    once = redactor.redact(f"token: {FAKE_SECRETS['GITHUB_TOKEN']}")
    assert once == "token: «REDACTED:env:GITHUB_TOKEN»"
    assert redactor.redact(once) == once


# ---------------------------------------------------------------- extra patterns


def test_extra_patterns_are_applied() -> None:
    redactor = Redactor({}, extra_patterns=[r"ACME-\d{6}"])
    assert redactor.redact("ticket ACME-123456") == "ticket «REDACTED:custom»"


@pytest.mark.parametrize(
    ("patterns", "message"),
    [
        (["("], "not a valid regular expression"),
        (["a*"], "matches the empty string"),
        (["x" * 201], "longer than"),
        ([f"p{i}" for i in range(21)], "at most 20"),
    ],
)
def test_bad_extra_patterns_are_a_config_error(patterns: list[str], message: str) -> None:
    with pytest.raises(UsageError, match=message) as info:
        Redactor({}, extra_patterns=patterns)
    assert info.value.exit_code is ExitCode.USAGE


# ---------------------------------------------------------------- the pre-write scan


def test_contains_secret_after_redaction_is_false(redactor: Redactor) -> None:
    text = " ".join([*FAKE_SECRETS.values(), *TOKENS.values()])
    assert redactor.contains_secret(text)
    assert not redactor.contains_secret(redactor.redact(text))


@pytest.mark.parametrize("encode", ["b64", "urlsafe", "percent"])
def test_contains_secret_catches_encoded_environment_values(encode: str) -> None:
    value = "secret/value+with spaces"
    redactor = Redactor({"MY_TOKEN": value})
    if encode == "b64":
        encoded = base64.b64encode(value.encode()).decode()
    elif encode == "urlsafe":
        encoded = base64.urlsafe_b64encode(value.encode()).decode()
    else:
        encoded = "secret%2Fvalue%2Bwith%20spaces"
    text = f"data: {encoded}"
    assert redactor.redact(text) == text  # encodings are not rewritten ...
    assert redactor.contains_secret(text)  # ... so the pre-write scan aborts the write


def test_contains_secret_sees_a_lone_private_key_header() -> None:
    assert Redactor({}).contains_secret("-----BEGIN OPENSSH PRIVATE " + "KEY-----")


def test_contains_secret_ignores_ordinary_text() -> None:
    assert not Redactor({"HOME": "/home/x"}).contains_secret("nothing to see, /home/x is fine")


# ---------------------------------------------------------------- logging


def make_record(msg: str, *args: object, exc: bool = False) -> logging.LogRecord:
    exc_info = None
    if exc:
        try:
            raise RuntimeError(f"boom {FAKE_SECRETS['OPENAI_API_KEY']}")
        except RuntimeError:
            exc_info = sys.exc_info()
    return logging.LogRecord("aipm", logging.ERROR, __file__, 1, msg, args, exc_info)


def test_logging_filter_redacts_message_args_and_tracebacks(
    redactor: Redactor, fake_secrets: FakeSecrets
) -> None:
    record = make_record("key %s", FAKE_SECRETS["ANTHROPIC_API_KEY"], exc=True)
    record.stack_info = f"stack {FAKE_SECRETS['GITHUB_TOKEN']}"
    assert redactor.logging_filter().filter(record)
    rendered = logging.Formatter().format(record)
    fake_secrets.assert_absent(rendered)
    assert "«REDACTED:env:ANTHROPIC_API_KEY»" in rendered
    assert "«REDACTED:env:OPENAI_API_KEY»" in rendered
    assert record.args is None


def test_logging_filter_survives_a_bad_format_string(redactor: Redactor) -> None:
    record = make_record("value %d", "not a number")
    assert redactor.logging_filter().filter(record)
    assert record.getMessage() == "value %d"


def test_logging_filter_redacts_existing_exception_text(redactor: Redactor) -> None:
    record = make_record("plain")
    record.exc_text = f"Traceback: {FAKE_SECRETS['GITHUB_TOKEN']}"
    redactor.logging_filter().filter(record)
    assert record.exc_text == "Traceback: «REDACTED:env:GITHUB_TOKEN»"


# ---------------------------------------------------------------- the process-wide factory


def test_process_redactor_is_built_from_the_full_environment(fake_secrets: FakeSecrets) -> None:
    redactor = process_redactor()
    assert redactor.env_names == frozenset(os.environ)
    fake_secrets.assert_absent(redactor.redact(" ".join(FAKE_SECRETS.values())))


def test_process_redactor_takes_extra_patterns() -> None:
    assert process_redactor([r"ACME-\d+"]).redact("ACME-1") == "«REDACTED:custom»"
