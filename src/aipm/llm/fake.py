"""FakeLLM: a deterministic provider for tests that records every request it receives.

It sits where a real provider sits, under the gateway, so a test sees exactly what would have been
sent: after rendering, spotlighting and redaction. Responses come from
`<fixtures_dir>/<fixture>/<role>.yaml`, a list consumed in order:

```yaml
responses:
  - json: {...}                  # a reply, serialized as JSON
  - raw: "not json"              # a reply as raw text, to exercise the repair path
  - error: rate_limit            # rate_limit | server | unsupported | fatal
    retry_after: 2
  - json: {...}
    stop: max_tokens             # end | max_tokens | refusal
```

Token counts are a deterministic estimate (four characters per token).
"""

import json
import re
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import Annotated, Any, Literal, Self

from pydantic import Field, JsonValue, ValidationError, model_validator

from aipm.domain.errors import UsageError
from aipm.domain.models import RoleName, StrictModel
from aipm.llm.errors import ProviderError, RetryableProviderError, UnsupportedStructuredOutput
from aipm.llm.providers.base import ProviderRequest, ProviderResponse, Stop, StructuredMode
from aipm.state.yamlio import load_yaml

_FIXTURE_NAME = re.compile(r"[a-z0-9][a-z0-9_\-]{0,63}")


class FakeResponse(StrictModel):
    """One canned reply or failure."""

    json_value: Annotated[dict[str, JsonValue] | None, Field(alias="json")] = None
    raw: str | None = None
    error: Literal["rate_limit", "server", "unsupported", "fatal"] | None = None
    retry_after: float | None = None
    stop: Stop = Stop.END

    @model_validator(mode="after")
    def _exactly_one(self) -> Self:
        given = [x for x in (self.json_value, self.raw, self.error) if x is not None]
        if len(given) != 1:
            raise ValueError("each fake response has exactly one of json, raw or error")
        return self


class _FixtureFile(StrictModel):
    responses: list[FakeResponse] = Field(max_length=200)


class FakeLLM:
    """Return fixture responses keyed by (role, fixture) and record every request."""

    name = "fake"

    def __init__(
        self,
        fixtures_dir: Path,
        fixture: str = "default",
        *,
        modes: tuple[StructuredMode, ...] = (StructuredMode.JSON_SCHEMA, StructuredMode.PROMPT),
    ) -> None:
        if not _FIXTURE_NAME.fullmatch(fixture):
            raise UsageError(f"not a fixture name: {fixture!r}")
        self.fixtures_dir = fixtures_dir
        self.fixture = fixture
        self.modes = modes
        self.requests: list[ProviderRequest] = []
        self._queues: dict[RoleName, list[FakeResponse]] = {}

    @classmethod
    def from_responses(
        cls,
        responses: Mapping[RoleName, Sequence[Mapping[str, Any]]],
        *,
        modes: tuple[StructuredMode, ...] = (StructuredMode.JSON_SCHEMA, StructuredMode.PROMPT),
    ) -> "FakeLLM":
        """A fake with inline responses instead of fixture files."""
        fake = cls(Path("/nonexistent"), "inline", modes=modes)
        for role, items in responses.items():
            fake._queues[role] = [FakeResponse.model_validate(item) for item in items]
        return fake

    def _queue(self, role: RoleName) -> list[FakeResponse]:
        if role not in self._queues:
            path = self.fixtures_dir / self.fixture / f"{role.value}.yaml"
            try:
                text = path.read_text(encoding="utf-8")
            except FileNotFoundError:
                raise ProviderError(f"FakeLLM: no {role.value} fixture in {self.fixture}") from None
            try:
                parsed = _FixtureFile.model_validate(load_yaml(text, source=str(path)))
            except ValidationError as exc:
                raise ProviderError(f"FakeLLM: {path} is not a valid fixture: {exc}") from None
            self._queues[role] = list(parsed.responses)
        return self._queues[role]

    def requests_for(self, role: RoleName) -> list[ProviderRequest]:
        """The recorded requests for one role, in order."""
        return [r for r in self.requests if r.role is role]

    def remaining(self, role: RoleName) -> int:
        """How many responses are left for a role."""
        return len(self._queue(role))

    def complete(self, request: ProviderRequest) -> ProviderResponse:
        """Record the request and return (or raise) the next canned response."""
        self.requests.append(request)
        queue = self._queue(request.role)
        if not queue:
            role = request.role.value
            raise ProviderError(f"FakeLLM: no {role} responses left in {self.fixture}")
        entry = queue.pop(0)
        if entry.error == "rate_limit":
            raise RetryableProviderError("fake rate limit (429)", retry_after=entry.retry_after)
        if entry.error == "server":
            raise RetryableProviderError("fake server error (500)", retry_after=entry.retry_after)
        if entry.error == "unsupported":
            raise UnsupportedStructuredOutput(f"fake: {request.mode.value} output is not supported")
        if entry.error == "fatal":
            raise ProviderError("fake fatal error (400)")
        if entry.json_value is not None:
            text = json.dumps(entry.json_value, ensure_ascii=False)
        else:
            text = entry.raw or ""
        return ProviderResponse(
            text=text,
            input_tokens=len(request.system + request.user) // 4 + 1,
            output_tokens=len(text) // 4 + 1,
            stop=entry.stop,
        )
