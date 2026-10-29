"""FakeLLM: deterministic fixture responses that record every request."""

from pathlib import Path

import pytest

from aipm.domain.errors import UsageError
from aipm.domain.models import RoleName
from aipm.llm.errors import ProviderError, RetryableProviderError, UnsupportedStructuredOutput
from aipm.llm.fake import FakeLLM
from aipm.llm.providers.base import ProviderRequest, Stop, StructuredMode
from tests.conftest import LLM_FIXTURES


def request(role: RoleName = RoleName.INTERVIEWER) -> ProviderRequest:
    return ProviderRequest(role=role, model="m", system="sys", user="user", max_output_tokens=10,
                           schema_name="S", schema={}, mode=StructuredMode.JSON_SCHEMA)  # fmt: skip


def test_fixture_responses_come_in_order_and_requests_are_recorded() -> None:
    fake = FakeLLM(LLM_FIXTURES, "clinic")
    first = fake.complete(request())
    second = fake.complete(request())
    assert '"one_liner": "Small clinics' in first.text
    assert '"Q-011"' in second.text
    assert fake.remaining(RoleName.INTERVIEWER) == 0
    assert len(fake.requests_for(RoleName.INTERVIEWER)) == 2
    with pytest.raises(ProviderError, match="no interviewer responses left"):
        fake.complete(request())
    assert len(fake.requests) == 3


def test_token_counts_are_deterministic() -> None:
    a = FakeLLM.from_responses({RoleName.INTERVIEWER: [{"raw": "abcd" * 10}]}).complete(request())
    b = FakeLLM.from_responses({RoleName.INTERVIEWER: [{"raw": "abcd" * 10}]}).complete(request())
    assert (a.input_tokens, a.output_tokens) == (b.input_tokens, b.output_tokens) == (2, 11)


@pytest.mark.parametrize(
    ("entry", "kind"),
    [
        ({"error": "rate_limit", "retry_after": 2}, RetryableProviderError),
        ({"error": "server"}, RetryableProviderError),
        ({"error": "unsupported"}, UnsupportedStructuredOutput),
        ({"error": "fatal"}, ProviderError),
    ],
)
def test_errors(entry: dict[str, object], kind: type[Exception]) -> None:
    fake = FakeLLM.from_responses({RoleName.INTERVIEWER: [entry]})
    with pytest.raises(kind):
        fake.complete(request())


def test_invalid_output_and_stop_reasons() -> None:
    fake = FakeLLM.from_responses(
        {RoleName.INTERVIEWER: [{"raw": "{not json"}, {"json": {"a": 1}, "stop": "refusal"}]}
    )
    assert fake.complete(request()).text == "{not json"
    assert fake.complete(request()).stop is Stop.REFUSAL


def test_bad_fixtures_are_rejected(tmp_path: Path) -> None:
    with pytest.raises(UsageError):
        FakeLLM(tmp_path, "../escape")
    with pytest.raises(ProviderError, match="no prd_writer fixture"):
        FakeLLM(tmp_path, "missing").complete(request(RoleName.PRD_WRITER))
    (tmp_path / "bad").mkdir()
    (tmp_path / "bad" / "interviewer.yaml").write_text(
        "responses:\n  - {json: {a: 1}, raw: x}\n", encoding="utf-8"
    )
    with pytest.raises(ProviderError, match="not a valid fixture"):
        FakeLLM(tmp_path, "bad").complete(request())


@pytest.mark.parametrize("fixture", sorted(p.name for p in LLM_FIXTURES.iterdir() if p.is_dir()))
def test_every_fixture_file_loads(fixture: str) -> None:
    fake = FakeLLM(LLM_FIXTURES, fixture)
    for path in (LLM_FIXTURES / fixture).glob("*.yaml"):
        assert fake.remaining(RoleName(path.stem)) > 0
