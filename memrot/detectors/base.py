"""Detector contract: given a piece of observed text and a canary, decide
whether the canary is present. Kept separate from the runner so a variant's
detection logic can be swapped (literal / ground-truth / phase-2 LLM-judge)
without touching the baseline/inject/consolidate/probe flow."""
from __future__ import annotations

import abc
from typing import Optional

from ..models import DetectionChannel, DetectionResult


class Detector(abc.ABC):
    kind: str = "abstract"

    @abc.abstractmethod
    def detect(self, text: Optional[str], canary: str, channel: DetectionChannel) -> DetectionResult:
        raise NotImplementedError
