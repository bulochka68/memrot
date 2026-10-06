from __future__ import annotations

import json
import uuid

import pytest

from memory_trace import TraceEvent
from memory_trace.emitter import TraceEmitter
from memory_trace.redaction import MODE_BASIC, SECRET_PLACEHOLDER, Redactor, canary_token
from memory_trace.schema import SchemaValidationError

SK = "sk-" + "A1b2C3d4E5" * 4
CANARY = "[H1-CCD9A7E7]"


def make_event(**extra) -> TraceEvent:
    data = {
        "schema_version": "0.1.0",
        "event_id": str(uuid.uuid4()),
        "run_id": "test_run",
        "trace_id": "trace-1",
        "agent_id": "agent-1",
        "principal": "attacker",
        "component": "session-finalizer",
        "ts": "2026-10-06T18:45:00Z",
        "stage": "candidate",
        "parent_event_refs": [],
        "_coverage": {"observed": True, "source": "agent", "partial": False},
    }
    data.update(extra)
    return TraceEvent.model_validate(data)


class SpyRedactor(Redactor):
    def __init__(self) -> None:
        super().__init__(api_url="")
        self.calls = 0

    def redact(self, text, canaries=None):
        self.calls += 1
        return super().redact(text, canaries)


def test_event_without_content_skips_redactor(no_presidio):
    spy = SpyRedactor()
    emitter = TraceEmitter(redactor=spy)

    emitter.emit(make_event())

    assert spy.calls == 0
    assert len(emitter.buffer) == 1
    assert emitter.buffer[0].content_redacted is None


def test_secret_in_content_full_is_redacted(no_presidio):
    emitter = TraceEmitter(redactor=Redactor())

    out = emitter.emit(make_event(content_full=f"key={SK}"))

    assert out.content_full == f"key={SECRET_PLACEHOLDER}"
    assert out.content_redacted is True
    assert out.redaction_mode == MODE_BASIC
    assert emitter.buffer == [out]


def test_canary_at_start_of_preview_is_hidden(no_presidio):
    emitter = TraceEmitter(redactor=Redactor())

    out = emitter.emit(make_event(content_preview=f"{CANARY} запомни правило"), canaries=[CANARY])

    assert CANARY not in out.content_preview
    assert out.content_preview.startswith(canary_token(CANARY))
    assert out.content_redacted is True


def test_invalid_event_raises_and_keeps_buffer(no_presidio):
    emitter = TraceEmitter()
    emitter.emit(make_event())
    # "saved" requires content_digest / operation / memory_layer (schema if/then)
    invalid = make_event(stage="saved")

    with pytest.raises(SchemaValidationError):
        emitter.emit(invalid)
    assert len(emitter.buffer) == 1


def test_flush_writes_default_path_and_clears_buffer(tmp_path, monkeypatch, no_presidio):
    monkeypatch.chdir(tmp_path)
    emitter = TraceEmitter(run_id="test_run")
    events = [emitter.emit(make_event()) for _ in range(3)]

    written = emitter.flush()

    path = tmp_path / "runs" / "test_run" / "trace.jsonl"
    lines = path.read_text(encoding="utf-8").splitlines()
    assert written == 3
    assert [json.loads(line)["event_id"] for line in lines] == [str(e.event_id) for e in events]
    assert emitter.buffer == []
