"""JSONL trace log.

Every request, response, memory inspection, ground-truth check and verdict
is logged as one :class:`TraceEvent`. Field names loosely mirror
``AUDIT_V2_CHANGE_SPEC.md`` §15.4's minimal trace schema (event_id, run_id,
trace_id, parent_event_refs, component, time, applicable identity; memory
and tool sub-fields) so that a future audit re-run could, in principle, feed
these events into ``mcp_audit``'s (currently unused) ``adapters/trace.py`` to
upgrade a hypothesis finding to ``runtime_supported``. That integration is
not built now -- this module only keeps the shape compatible.

Raw message text is never logged by default: only a bounded, escaped
fragment plus a sha256 digest, so a trace file can be shared without leaking
full conversation content.
"""
from __future__ import annotations

import hashlib
import json
import time
import uuid
from dataclasses import dataclass, field, fields
from typing import Any, Dict, List, Optional

from . import ATTACK_SCHEMA_VERSION
from .models import plain


def _digest(text: str) -> str:
    return "sha256:" + hashlib.sha256(text.encode("utf-8")).hexdigest()


def _fragment(text: str, limit: int = 300) -> str:
    s = text.replace("\r", " ").replace("\n", " / ")
    return s if len(s) <= limit else s[:limit] + "…"


@dataclass
class TraceEvent:
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
    def __init__(self, path: Optional[str] = None) -> None:
        self.path = path
        self.events: List[TraceEvent] = []
        self._fh = open(path, "w", encoding="utf-8") if path else None

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
        if self._fh is not None:
            self._fh.write(json.dumps(event.to_dict(), ensure_ascii=False) + "\n")
            self._fh.flush()
        return event

    def close(self) -> None:
        if self._fh is not None:
            self._fh.close()
            self._fh = None
