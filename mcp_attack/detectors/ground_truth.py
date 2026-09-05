from __future__ import annotations

from typing import Optional

from ..models import DetectionChannel, DetectionResult
from .base import Detector


class GroundTruthDetector(Detector):
    """Names/documents the ground-truth channel. The runner calls
    ``adapter.ground_truth_check()`` directly and wraps the ``Optional[bool]``
    it returns into a :class:`DetectionResult` via :meth:`wrap` -- this class
    is not itself given raw response text (there is none: ground truth is an
    out-of-band signal, e.g. a backend access-log grep, independent of what
    the model's response claims)."""
    kind = "ground_truth"

    def detect(self, text: Optional[str], canary: str, channel: DetectionChannel) -> DetectionResult:
        raise NotImplementedError("GroundTruthDetector.wrap(present) is used instead of .detect()")

    @staticmethod
    def wrap(present: Optional[bool], detail: str = "") -> Optional[DetectionResult]:
        if present is None:
            return None
        return DetectionResult(canary_present=present, channel=DetectionChannel.GROUND_TRUTH,
                               detail=detail or f"ground truth signal: {present}")
