from __future__ import annotations

from typing import Optional

from ..models import DetectionChannel, DetectionResult
from .base import Detector


class LiteralDetector(Detector):
    """Exact/substring canary match. Fast; breaks if the target paraphrases
    memory into a summary and loses the literal token -- use a ground-truth
    or (phase 2) LLM-judge channel in that case."""
    kind = "literal"

    def __init__(self, case_sensitive: bool = False) -> None:
        self.case_sensitive = case_sensitive

    def detect(self, text: Optional[str], canary: str, channel: DetectionChannel) -> DetectionResult:
        if text is None or not canary:
            return DetectionResult(canary_present=False, channel=channel, detail="no text to inspect")
        haystack, needle = (text, canary) if self.case_sensitive else (text.lower(), canary.lower())
        present = needle in haystack
        return DetectionResult(canary_present=present, channel=channel,
                               detail=f"literal substring match: {present}")
