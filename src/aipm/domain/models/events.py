"""Run-journal events (ARCHITECTURE §6.3) and security events (`.pm/events.jsonl`, §6.1)."""

import json
from enum import StrEnum
from typing import Annotated, Literal, Self

from pydantic import AwareDatetime, Field, JsonValue, field_validator, model_validator

from aipm.domain.models.base import EventId, RunId, Str200, Str1000, StrictModel, TaskId

MAX_EVENT_DATA_BYTES = 16_384
MAX_EVENT_DATA_KEYS = 64


def _check_data(data: dict[str, JsonValue]) -> dict[str, JsonValue]:
    if len(data) > MAX_EVENT_DATA_KEYS:
        raise ValueError(f"at most {MAX_EVENT_DATA_KEYS} data keys")
    if len(json.dumps(data, ensure_ascii=True)) > MAX_EVENT_DATA_BYTES:
        raise ValueError(f"data is larger than {MAX_EVENT_DATA_BYTES} bytes")
    return data


class JournalEventType(StrEnum):
    """Run-journal event types (ARCHITECTURE §6.3)."""

    RUN_STARTED = "run_started"
    TASK_SCHEDULED = "task_scheduled"
    WORKTREE_CREATED = "worktree_created"
    PROMPT_COMPILED = "prompt_compiled"
    AGENT_STARTED = "agent_started"
    AGENT_FINISHED = "agent_finished"
    CHECK_RESULT = "check_result"
    POLICY_VIOLATION = "policy_violation"
    GATE_RESULT = "gate_result"
    TASK_COMMITTED = "task_committed"
    TASK_MERGED = "task_merged"
    TASK_BLOCKED = "task_blocked"
    BUDGET_EXCEEDED = "budget_exceeded"
    INTERRUPTED = "interrupted"
    RUN_FINISHED = "run_finished"


class JournalEvent(StrictModel):
    """One line of `runs/<run-id>/journal.jsonl`."""

    v: Literal[1] = 1
    seq: Annotated[int, Field(ge=0)]
    ts: AwareDatetime
    run: RunId
    type: JournalEventType
    task: TaskId | None = None
    attempt: Annotated[int, Field(ge=0, le=100)] | None = None
    data: dict[str, JsonValue] = Field(default_factory=dict)

    @field_validator("data")
    @classmethod
    def _bounded_data(cls, data: dict[str, JsonValue]) -> dict[str, JsonValue]:
        return _check_data(data)


class SecurityEventKind(StrEnum):
    """Signals recorded in `.pm/events.jsonl` (SECURITY.md §7.9)."""

    INJECTION_SIGNAL = "injection_signal"
    POLICY_VIOLATION = "policy_violation"
    POST_CHANGE_VIOLATION = "post_change_violation"
    FORBIDDEN_FLAG = "forbidden_flag"
    OVERRIDE = "override"
    TASK_CHANGE = "task_change"
    ACK = "ack"


class SecurityEvent(StrictModel):
    """One line of `.pm/events.jsonl`. IDs are random, so they cannot be acknowledged ahead."""

    v: Literal[1] = 1
    id: EventId
    ts: AwareDatetime
    kind: SecurityEventKind
    source: Str200 = ""
    detail: Str1000 = ""
    ack_of: EventId | None = None
    data: dict[str, JsonValue] = Field(default_factory=dict)

    @field_validator("data")
    @classmethod
    def _bounded_data(cls, data: dict[str, JsonValue]) -> dict[str, JsonValue]:
        return _check_data(data)

    @model_validator(mode="after")
    def _ack(self) -> Self:
        if (self.kind is SecurityEventKind.ACK) != (self.ack_of is not None):
            raise ValueError("'ack_of' is set exactly on ack events")
        return self
