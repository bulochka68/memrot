"""Attack trace: phase log in memory, memory-lifecycle events on disk.

Two streams:

* :meth:`JSONLTracer.log` records attack *phases* (request, response,
  inspection, verdict, skip, error) as legacy :class:`TraceEvent` objects in
  ``tracer.events``. They are kept in memory only: they do not fit the
  memory-trace schema, which has no stage for a verdict or a skip.
* :meth:`JSONLTracer.lifecycle` builds a ``memory_trace.TraceEvent``
  (schema ``memory-trace-0.1``) and hands it to a
  :class:`memory_trace.emitter.TraceEmitter`, which redacts secrets and the
  canary, validates the event and buffers it. :meth:`flush` / :meth:`close`
  append the buffer to ``path`` as JSONL.

Raw text is never written: a lifecycle event carries a sha256 digest, the
length and a bounded, redacted preview, never ``content_full``.
"""
from __future__ import annotations

import hashlib
import logging
import time
import uuid
from dataclasses import dataclass, field, fields
from datetime import datetime, timezone
from typing import Any, Dict, Iterable, List, Optional

from memory_trace import TraceEvent as MemoryTraceEvent
from memory_trace.emitter import TraceEmitter
from memory_trace.redaction import Redactor

from . import ATTACK_SCHEMA_VERSION
from .models import plain

log = logging.getLogger(__name__)

MEMORY_TRACE_SCHEMA_VERSION = "0.1.0"
_ID_MAX_LENGTH = 128   # schema maxLength for run_id / trace_id / agent_id / component / session_id
_PREVIEW_LIMIT = 200   # leaves room for CANARY_<hash> tokens under the schema's 256


def _digest(text: str) -> str:
    return "sha256:" + hashlib.sha256(text.encode("utf-8")).hexdigest()


def _fragment(text: str, limit: int = 300) -> str:
    s = text.replace("\r", " ").replace("\n", " / ")
    return s if len(s) <= limit else s[:limit] + "…"


def _bounded_id(value: Optional[str]) -> Optional[str]:
    if value is None or value == "":
        return None
    return str(value)[:_ID_MAX_LENGTH]


@dataclass
class TraceEvent:
    """Legacy attack-phase event (in-memory only, see module docstring)."""

    event_id: str
    run_id: str
    trace_id: str                                    # groups events by variant (variant.id)
    parent_event_refs: List[str] = field(default_factory=list)
    component: str = "memrot.runner"
    ts: float = field(default_factory=time.time)
    config_version: str = ATTACK_SCHEMA_VERSION
    principal: Optional[str] = None
    phase: Optional[str] = None       # baseline | inject | consolidate | probe | memory_inspection | ground_truth | verdict | skip | error
    channel_id: Optional[str] = None
    session_id: Optional[str] = None
    direction: Optional[str] = None    # request | response | inspection | decision
    text_digest: Optional[str] = None
    text_fragment: Optional[str] = None
    canary: Optional[str] = None
    canary_present: Optional[bool] = None
    memory: Dict[str, Any] = field(default_factory=dict)
    tool: Dict[str, Any] = field(default_factory=dict)
    verdict: Optional[str] = None
    error: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return plain({f.name: getattr(self, f.name) for f in fields(self)})


class JSONLTracer:
    def __init__(self, path: Optional[str] = None, *, run_id: Optional[str] = None,
                 redactor: Optional[Redactor] = None, validate: bool = True) -> None:
        self.path = path
        self.events: List[TraceEvent] = []
        self.redactor = redactor if redactor is not None else Redactor()
        self.emitter = TraceEmitter(self.redactor, validate=validate, run_id=run_id)
        # lifecycle events that could not be emitted; tracing must never fail an attack
        self.lifecycle_errors: List[str] = []
        if path:
            # one trace per run: start empty (flush appends) and exist even if nothing is emitted
            open(path, "w", encoding="utf-8").close()

    @property
    def lifecycle_events(self) -> List[MemoryTraceEvent]:
        """Emitted lifecycle events not yet flushed to disk."""
        return self.emitter.buffer

    def log(self, *, run_id: str, trace_id: str, text: Optional[str] = None, **kwargs: Any) -> TraceEvent:
        event = TraceEvent(
            event_id=f"evt-{uuid.uuid4().hex[:12]}",
            run_id=run_id,
            trace_id=trace_id,
            text_digest=_digest(text) if text is not None else None,
            text_fragment=_fragment(text) if text is not None else None,
            **kwargs,
        )
        self.events.append(event)
        return event

    def lifecycle(self, *, run_id: str, trace_id: str, agent_id: str, stage: str, principal: str,
                  observed: bool, source: str, partial: bool = True,
                  text: Optional[str] = None, canary: Optional[str] = None,
                  parents: Iterable[MemoryTraceEvent] = (), session_id: Optional[str] = None,
                  component: str = "memrot.runner", **fields: Any) -> Optional[MemoryTraceEvent]:
        """Emit one memory-trace event; return it, or ``None`` if it was rejected.

        ``fields`` are passed straight to the memory-trace model
        (``operation``, ``memory_layer``, ``evidence_tier``, ...).
        """
        data: Dict[str, Any] = dict(
            schema_version=MEMORY_TRACE_SCHEMA_VERSION,
            event_id=uuid.uuid4(),
            run_id=_bounded_id(run_id),
            trace_id=_bounded_id(trace_id),
            agent_id=_bounded_id(agent_id) or "unknown",
            principal=principal,
            component=component,
            ts=datetime.now(timezone.utc),
            config_version=ATTACK_SCHEMA_VERSION,
            stage=stage,
            parent_event_refs=[p.event_id for p in parents if p is not None],
            coverage={"observed": observed, "source": source, "partial": partial},
            **fields,
        )
        if session_id is not None:
            data["session_id"] = _bounded_id(session_id)
        if text is not None:
            data.update(content_digest=_digest(text), content_length=len(text),
                        content_preview=_fragment(text, _PREVIEW_LIMIT))
        try:
            event = MemoryTraceEvent.model_validate(data)
            return self.emitter.emit(event, canaries=[canary] if canary else None)
        except Exception as exc:  # noqa: BLE001 -- a bad trace event must not turn a variant into ERROR
            message = f"{stage} event for {trace_id!r} dropped: {type(exc).__name__}: {exc}"
            self.lifecycle_errors.append(message)
            log.warning(message)
            return None

    def flush(self) -> int:
        """Append buffered lifecycle events to ``path``; return how many were written.

        Without ``path`` (and without ``run_id`` for the emitter's default
        ``runs/<run_id>/trace.jsonl``) events stay in memory.
        """
        if self.path:
            return self.emitter.flush(self.path)
        if self.emitter.run_id:
            return self.emitter.flush()
        return 0

    def close(self) -> None:
        self.flush()
