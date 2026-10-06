from __future__ import annotations

import copy
import uuid

import pytest
from pydantic import ValidationError

from memory_trace import Stage, TraceEvent
from memory_trace.schema import SchemaValidationError, validate_event

DIGEST = "sha256:" + "a" * 64


@pytest.fixture
def saved_event() -> dict:
    return {
        "schema_version": "0.1.0",
        "event_id": str(uuid.uuid4()),
        "run_id": "run-h1-001",
        "trace_id": "agent-invest-1",
        "agent_id": "genai-invest-agent",
        "session_id": "h1-1-ab12cd34",
        "principal": "attacker",
        "component": "session-finalizer",
        "ts": "2026-10-06T18:45:00Z",
        "config_version": "c1",
        "stage": "saved",
        "parent_event_refs": [str(uuid.uuid4())],
        "_coverage": {"observed": True, "source": "memory_store", "partial": False},
        "content_digest": DIGEST,
        "content_preview": "Пользователь хочет метку [H1-CCD9A7E7]",
        "content_redacted": False,
        "content_length": 38,
        "writer_id": "session-finalizer",
        "channel_id": "attacker:1001",
        "operation": "write",
        "memory_layer": "semantic",
        "finalize_scopes": {"requested_scopes": ["global"], "actual_scopes": ["user"], "facts_digest": [DIGEST]},
        "chain_break_reason": "scope_mismatch",
        "evidence_tier": "state",
        "evidence_kind": "hard",
    }


def _fails_at(event: dict, path: str) -> SchemaValidationError:
    with pytest.raises(SchemaValidationError) as exc:
        validate_event(event)
    assert exc.value.path == path, exc.value.errors
    assert path in str(exc.value)
    return exc.value


# -- 1. valid ---------------------------------------------------------------- #

def test_full_saved_event_is_valid(saved_event):
    validate_event(saved_event)


def test_model_round_trip_passes_schema(saved_event):
    event = TraceEvent.model_validate(saved_event)
    assert event.stage is Stage.SAVED
    validate_event(event.to_dict())


# -- 2-3. stage-specific required fields -------------------------------------- #

def test_saved_without_content_digest_fails(saved_event):
    del saved_event["content_digest"]
    _fails_at(saved_event, "$.content_digest")


def test_in_prompt_without_context_role_fails(saved_event):
    saved_event["stage"] = "in_prompt"
    saved_event["included_in_context"] = True
    _fails_at(saved_event, "$.context_role")


# -- 4-5. retrieval metrics --------------------------------------------------- #

def test_retrieval_score_without_method_fails(saved_event):
    saved_event.update(stage="retrieved", retrieval_score=0.82, rank_position=0, experimental=True)
    _fails_at(saved_event, "$.retrieval_method")


def test_retrieval_metrics_with_experimental_false_fails(saved_event):
    saved_event.update(stage="retrieved", retrieval_score=0.82, retrieval_method="dense",
                       rank_position=0, experimental=False)
    _fails_at(saved_event, "$.experimental")


def test_retrieval_metrics_with_experimental_true_is_valid(saved_event):
    saved_event.update(stage="retrieved", embedding_score=0.9, retrieval_score=0.82,
                       retrieval_method="hybrid", rank_position=0, top_k=5, experimental=True)
    validate_event(saved_event)


# -- 6-7. envelope ------------------------------------------------------------- #

def test_missing_coverage_fails(saved_event):
    del saved_event["_coverage"]
    _fails_at(saved_event, "$._coverage")


def test_unknown_field_fails(saved_event):
    saved_event["some_random_field"] = "x"
    _fails_at(saved_event, "$.some_random_field")


# -- 8. formats ---------------------------------------------------------------- #

def test_parent_event_ref_not_uuid_fails(saved_event):
    saved_event["parent_event_refs"] = ["not-a-uuid"]
    _fails_at(saved_event, "$.parent_event_refs[0]")


def test_event_id_not_uuid_fails(saved_event):
    saved_event["event_id"] = "evt-123"
    _fails_at(saved_event, "$.event_id")


@pytest.mark.parametrize("ts", ["2026-10-06 18:45", "2026-10-06T18:45:00", "not-a-date"])
def test_invalid_date_time_fails(saved_event, ts):
    saved_event["ts"] = ts
    _fails_at(saved_event, "$.ts")


def test_non_uuid_ids_stay_plain_strings(saved_event):
    saved_event.update(run_id="run-1", trace_id="agent-a", agent_id="agent-a")
    validate_event(saved_event)


# -- session_id ---------------------------------------------------------------- #

def test_session_id_absent_is_valid(saved_event):
    del saved_event["session_id"]
    validate_event(saved_event)
    assert "session_id" not in TraceEvent.model_validate(saved_event).to_dict()


def test_session_id_null_is_valid(saved_event):
    saved_event["session_id"] = None
    validate_event(saved_event)
    assert TraceEvent.model_validate(saved_event).to_dict()["session_id"] is None


def test_session_id_string_is_valid(saved_event):
    saved_event["session_id"] = "abc"
    validate_event(saved_event)
    assert TraceEvent.model_validate(saved_event).to_dict()["session_id"] == "abc"


def test_session_id_empty_string_fails(saved_event):
    saved_event["session_id"] = ""
    _fails_at(saved_event, "$.session_id")
    with pytest.raises(ValidationError):
        TraceEvent.model_validate(copy.deepcopy(saved_event))
