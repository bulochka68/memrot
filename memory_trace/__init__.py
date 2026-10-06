"""memory_trace -- lifecycle events for agent memory (schema memory-trace 0.1).

One event per lifecycle stage of a memory record:
candidate -> saved -> retrieved -> in_prompt -> used_in_reasoning ->
influenced_action -> caused_harm.

Contract: ``schemas/memory-trace-0.1.schema.json``.
"""
from __future__ import annotations

from .models import (
    ChainBreakReason,
    Coverage,
    EvidenceTier,
    MemoryLayer,
    Operation,
    Principal,
    Stage,
    TraceEvent,
)

__version__ = "0.1.0"

__all__ = [
    "TraceEvent",
    "Principal",
    "Coverage",
    "ChainBreakReason",
    "EvidenceTier",
    "MemoryLayer",
    "Operation",
    "Stage",
    "__version__",
]
