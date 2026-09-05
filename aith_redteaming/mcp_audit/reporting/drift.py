"""P8 drift mode: run layers 1-2 only and compare against a stored baseline."""
from __future__ import annotations

from typing import Any, Dict, Optional

from ..models import AuditDocument
from .baseline import diff_baseline, load_baseline


def run_drift(doc: AuditDocument, baseline_path: str) -> Dict[str, Any]:
    old = load_baseline(baseline_path)
    result = diff_baseline(old, doc)
    doc.drift = result
    return result
