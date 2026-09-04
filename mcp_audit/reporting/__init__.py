"""Layer 6 - Findings & Reporting + P8 drift detection.

Emits the canonical ``audit`` JSON, stores the hash/capability baseline, and
maps findings to downstream pipeline artifacts (P2 threat-model matrix,
P3 attack corpus, P8 drift).
"""
from .emitter import emit_json, emit_markdown, build_downstream
from .baseline import save_baseline, load_baseline, diff_baseline
from .drift import run_drift

__all__ = ["emit_json", "emit_markdown", "build_downstream", "save_baseline",
           "load_baseline", "diff_baseline", "run_drift"]
