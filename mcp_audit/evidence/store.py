"""Evidence store.

* Every piece of evidence gets a *stable* id derived from its source type,
  method, locator and digest - never from the order of collection.
* Fragments are bounded and secret-redacted before they are stored, so that
  tokens and real secrets never reach the report (TZ §14.8).
* Claims link to evidence by id; the store refuses dangling references so
  the emitted document always passes referential validation.
"""
from __future__ import annotations

import re
import time
from typing import Any, Dict, Iterable, List, Optional

from ..models import (AuditDocument, Claim, ClaimStatus, Confidence, Evidence, Method,
                      SourceType, stable_id)

MAX_FRAGMENT = 600

SECRET_PATTERNS = [
    re.compile(r"(?i)(bearer\s+)[A-Za-z0-9\-._~+/]+=*"),
    re.compile(r"(?i)\b(sk-[A-Za-z0-9_\-]{8,})"),
    re.compile(r"(?i)\b(eyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{5,})"),
    re.compile(r"(?i)((?:api[_-]?key|token|secret|password|passwd|client_secret|authorization)\s*[:=]\s*['\"]?)([^\s'\",;]{4,})"),
    re.compile(r"(?i)(://[^/\s:@]+:)([^@\s/]+)(@)"),   # user:password@host
]


def redact_secrets(text: str) -> str:
    """Replace secret-looking values with ``[REDACTED]``; keys are kept."""
    if not text:
        return text
    out = text
    out = SECRET_PATTERNS[0].sub(lambda m: m.group(1) + "[REDACTED]", out)
    out = SECRET_PATTERNS[1].sub("[REDACTED]", out)
    out = SECRET_PATTERNS[2].sub("[REDACTED]", out)
    out = SECRET_PATTERNS[3].sub(lambda m: m.group(1) + "[REDACTED]", out)
    out = SECRET_PATTERNS[4].sub(lambda m: m.group(1) + "[REDACTED]" + m.group(3), out)
    return out


def bound_fragment(text: Optional[str], limit: int = MAX_FRAGMENT) -> Optional[str]:
    if text is None:
        return None
    text = redact_secrets(str(text))
    if len(text) > limit:
        return text[:limit] + f"… [+{len(text) - limit} chars truncated]"
    return text


class EvidenceStore:
    """Registers evidence and claims on an :class:`AuditDocument`."""

    def __init__(self, doc: AuditDocument):
        self.doc = doc
        self._by_id: Dict[str, Evidence] = {e.evidence_id: e for e in doc.evidence}
        self._claims: Dict[str, Claim] = {c.claim_id: c for c in doc.claims}

    # -- evidence ----------------------------------------------------------- #
    def add(self, source_type: SourceType, method: Method, locator: Dict[str, Any], *,
            digest: Optional[str] = None, summary: str = "", fragment: Optional[str] = None,
            scope: Optional[Dict[str, Any]] = None, limitations: Optional[Iterable[str]] = None,
            adapter: Optional[str] = None, adapter_version: Optional[str] = None,
            captured_at: Optional[float] = None, extensions: Optional[Dict[str, Any]] = None,
            evidence_id: Optional[str] = None) -> Evidence:
        eid = evidence_id or stable_id("E", source_type.value, method.value, locator, digest)
        if eid in self._by_id:
            ev = self._by_id[eid]
            for lim in (limitations or []):
                if lim not in ev.limitations:
                    ev.limitations.append(lim)
            if fragment and not ev.fragment:
                ev.fragment = bound_fragment(fragment)
            return ev
        scope = dict(scope or {})
        # scope is inherited from the immutable run snapshot unless the evidence says otherwise (TZ §15.3)
        for key in ("build_ref", "environment"):
            if key not in scope and self.doc.target.get(key):
                scope[key] = self.doc.target[key]
        ev = Evidence(
            evidence_id=eid, source_type=source_type, method=method, locator=dict(locator),
            digest=digest, captured_at=captured_at if captured_at is not None else time.time(),
            adapter=adapter, adapter_version=adapter_version, scope=scope,
            summary=redact_secrets(summary), fragment=bound_fragment(fragment),
            limitations=list(limitations or []), extensions=dict(extensions or {}),
        )
        self._by_id[eid] = ev
        self.doc.evidence.append(ev)
        return ev

    def get(self, evidence_id: str) -> Optional[Evidence]:
        return self._by_id.get(evidence_id)

    def has(self, evidence_id: str) -> bool:
        return evidence_id in self._by_id

    # -- claims ------------------------------------------------------------- #
    def claim(self, claim_id: str, statement: str, status: ClaimStatus, *,
              evidence_refs: Iterable[str] = (), scope: Optional[Dict[str, Any]] = None,
              confidence: Confidence = Confidence.UNKNOWN, explanation: str = "",
              limitations: Optional[Iterable[str]] = None, rule_refs: Iterable[str] = (),
              component_refs: Iterable[str] = (), source_type: Optional[SourceType] = None,
              method: Optional[Method] = None) -> Claim:
        refs = [r for r in evidence_refs]
        missing = [r for r in refs if r not in self._by_id]
        if missing:
            raise ValueError(f"claim {claim_id} references unknown evidence {missing}")
        if status == ClaimStatus.RUNTIME_SUPPORTED:
            from ..models import RUNTIME_SOURCE_TYPES
            if not any(self._by_id[r].source_type in RUNTIME_SOURCE_TYPES for r in refs):
                raise ValueError(f"claim {claim_id}: runtime_supported requires runtime evidence")
        if claim_id in self._claims:
            c = self._claims[claim_id]
            for r in refs:
                if r not in c.evidence_refs:
                    c.evidence_refs.append(r)
            for lim in (limitations or []):
                if lim not in c.limitations:
                    c.limitations.append(lim)
            for r in rule_refs:
                if r not in c.rule_refs:
                    c.rule_refs.append(r)
            return c
        c = Claim(
            claim_id=claim_id, statement=statement, claim_status=status, evidence_refs=refs,
            scope=dict(scope or {}), confidence=confidence, confidence_explanation=explanation,
            limitations=list(limitations or []), rule_refs=list(rule_refs),
            component_refs=list(component_refs), source_type=source_type, method=method,
        )
        self._claims[claim_id] = c
        self.doc.claims.append(c)
        return c

    def get_claim(self, claim_id: str) -> Optional[Claim]:
        return self._claims.get(claim_id)

    def claims_with_rule(self, rule_id: str) -> List[Claim]:
        return [c for c in self.doc.claims if rule_id in c.rule_refs]
