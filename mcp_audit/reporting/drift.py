"""Baseline-comparison mode helpers (kept for import compatibility)."""
from __future__ import annotations

from typing import Any, Dict, Optional

from ..models import AuditDocument
from .baseline import run_drift as _run_drift


def run_drift(doc: AuditDocument, baseline_path: str, store=None, approvals_path: Optional[str] = None) -> Dict[str, Any]:
    return _run_drift(doc, baseline_path, store, approvals_path=approvals_path)
