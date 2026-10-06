"""In-memory trace buffer with redaction, schema validation and JSONL flush."""
from __future__ import annotations

import json
import os
from pathlib import Path
from typing import List, Optional, Union

from .models import TraceEvent
from .redaction import MODE_BASIC, MODE_FULL, Redactor
from .schema import validate_event

PREVIEW_MAX_LENGTH = 256   # schema: content_preview.maxLength


class TraceEmitter:
    def __init__(self, redactor: Optional[Redactor] = None, validate: bool = True,
                 run_id: Optional[str] = None) -> None:
        self.redactor = redactor
        self.validate = validate
        self.run_id = run_id
        self.buffer: List[TraceEvent] = []

    def emit(self, event: TraceEvent, canaries: Optional[List[str]] = None) -> TraceEvent:
        """Redact, validate and buffer a copy of ``event``; return the buffered copy.

        The caller's object is never buffered itself: mutating it after emit
        must not put unredacted content back into the trace.
        """
        event = event.model_copy(deep=True)
        if self.redactor is not None:
            modes = []
            for name in ("content_full", "content_preview"):
                value = getattr(event, name)
                if value is None:
                    continue
                result = self.redactor.redact(value, canaries)
                text = result.text
                if name == "content_preview":
                    # canary tokens can be longer than the canary they replace
                    text = text[:PREVIEW_MAX_LENGTH]
                setattr(event, name, text)
                modes.append(result.mode)
            if modes:
                event.content_redacted = True
                event.redaction_mode = MODE_BASIC if MODE_BASIC in modes else MODE_FULL
        if self.validate:
            validate_event(event.to_dict())
        self.buffer.append(event)
        return event

    def flush(self, filepath: Optional[Union[str, os.PathLike]] = None) -> int:
        """Append buffered events to a JSONL file; return how many were written.

        The buffer is cleared only after the data is fsync'ed; on any error it
        is left intact and the exception propagates.
        """
        pending = list(self.buffer)
        if not pending:
            return 0
        path = Path(filepath) if filepath is not None else self._default_path()
        payload = "".join(json.dumps(e.to_dict(), ensure_ascii=False) + "\n" for e in pending)
        path.parent.mkdir(parents=True, exist_ok=True)
        with open(path, "a", encoding="utf-8", newline="\n") as fh:
            fh.write(payload)
            fh.flush()
            os.fsync(fh.fileno())
        # events emitted while writing stay buffered for the next flush
        del self.buffer[:len(pending)]
        return len(pending)

    def _default_path(self) -> Path:
        if not self.run_id:
            raise ValueError("flush() needs a filepath or TraceEmitter(run_id=...)")
        return Path("runs") / self.run_id / "trace.jsonl"
