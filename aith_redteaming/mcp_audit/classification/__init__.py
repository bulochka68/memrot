"""Layer 3 - Classification & Risk.

Turns raw tools into normalized records: operation class, risk score,
destructiveness, and the effective (not declared) access scope.
"""
from .classifier import classify_tool, classify_all
from .risk import score_tool
from .effective_access import resolve_effective_access

__all__ = ["classify_tool", "classify_all", "score_tool", "resolve_effective_access"]
