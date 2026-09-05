from .base import Detector
from .ground_truth import GroundTruthDetector
from .literal import LiteralDetector

_REGISTRY = {"literal": LiteralDetector, "ground_truth": GroundTruthDetector}


def build_detector(kind: str, options: dict) -> Detector:
    cls = _REGISTRY.get(kind)
    if cls is None:
        raise ValueError(f"unknown detector kind {kind!r}; known kinds: {sorted(_REGISTRY)}")
    return cls(**options)


__all__ = ["Detector", "LiteralDetector", "GroundTruthDetector", "build_detector"]
