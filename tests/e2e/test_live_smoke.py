"""Live smoke test against the provider in your user config (never in CI).

Skipped unless `AIPM_LIVE=1`. It makes one real interviewer call through the real gateway and
checks that the reply validates. See tests/e2e/README.md for running it against Ollama.
"""

import pytest

from aipm.config.loader import load_config
from aipm.domain.models import RoleName
from aipm.llm.gateway import TokenBudget, open_gateway
from aipm.observability.redaction import process_redactor
from aipm.roles import interviewer
from aipm.security.untrusted import Untrusted
from tests.conftest import REPO_ROOT


@pytest.mark.live
@pytest.mark.enable_socket
def test_one_interviewer_round_against_the_configured_provider() -> None:
    llm = load_config(None).config.llm
    gateway = open_gateway(llm, redactor=process_redactor())
    role = interviewer.create()
    idea = (REPO_ROOT / "examples/clinic-booking/idea.md").read_text(encoding="utf-8")
    inp = interviewer.InterviewerInput(
        project="clinic-booking",
        round=1,
        extract=True,
        questions_per_round=3,
        scores={},
        requirements=Untrusted("answers: []\n", source="draft:requirements"),
        used_ids=frozenset(),
        idea=Untrusted(idea, source="file:examples/clinic-booking/idea.md"),
    )
    result = gateway.run(
        RoleName.INTERVIEWER, role.render(inp), interviewer.InterviewRound,
        budget=TokenBudget(200_000),
    )  # fmt: skip
    out = role.postprocess(result.value, inp)
    assert out.extracted or out.questions
    assert result.input_tokens > 0
    assert result.output_tokens > 0
