"""Adapter contract (TZ §5.3).

An adapter turns one kind of source into normalized evidence and entities.
It must declare ``adapter_version``, the capabilities it supports and the
explicit reasons for what it does not support.  Unknown fields of the source
are kept as namespaced extensions, never dropped silently.  An adapter never
guesses: what it cannot read stays ``unavailable`` / ``partial`` / ``stale``.
"""
from __future__ import annotations

import os
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

from ..models import AdapterStatus, AuditDocument
from ..evidence import EvidenceStore


@dataclass
class AdapterBinding:
    adapter_id: str
    kind: str
    binding: Dict[str, Any] = field(default_factory=dict)
    options: Dict[str, Any] = field(default_factory=dict)
    base_dir: str = "."

    def path(self, key: str = "path") -> Optional[str]:
        p = self.binding.get(key)
        if not p:
            return None
        if os.path.isabs(p):
            return p
        return os.path.normpath(os.path.join(self.base_dir, p))


@dataclass
class AdapterResult:
    status: AdapterStatus
    facts: Dict[str, Any] = field(default_factory=dict)


class Adapter:
    kind: str = "abstract"
    adapter_version: str = "0.0.0"
    supported: List[str] = []
    unsupported: Dict[str, str] = {}
    allowed_modes: Optional[List[str]] = None     # None = any mode

    def __init__(self, binding: AdapterBinding):
        self.binding = binding

    def status(self, state: str, reasons: Optional[List[str]] = None, captured_at: Optional[float] = None,
               evidence_count: int = 0) -> AdapterStatus:
        return AdapterStatus(
            adapter_id=self.binding.adapter_id, kind=self.kind, adapter_version=self.adapter_version,
            status=state, supported=list(self.supported), unsupported=dict(self.unsupported),
            reasons=list(reasons or []), binding={k: v for k, v in self.binding.binding.items() if k != "secret"},
            captured_at=captured_at, evidence_count=evidence_count,
        )

    def collect(self, doc: AuditDocument, store: EvidenceStore) -> AdapterResult:  # pragma: no cover - abstract
        raise NotImplementedError

    # helper for adapters that read a JSON file
    def _read_json(self, path: Optional[str]) -> Any:
        import json
        if not path:
            raise FileNotFoundError("no path bound")
        with open(path, "r", encoding="utf-8") as fh:
            text = fh.read()
        if path.endswith((".yaml", ".yml")):
            try:
                import yaml  # type: ignore
            except ImportError as e:
                raise RuntimeError("PyYAML is not installed; provide a JSON snapshot instead") from e
            return yaml.safe_load(text)
        if path.endswith(".jsonl"):
            return [json.loads(line) for line in text.splitlines() if line.strip()]
        from ..discovery.config_parser import _strip_json_comments
        return json.loads(_strip_json_comments(text))
