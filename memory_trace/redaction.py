"""Redaction of trace content before it leaves the process.

Level 1 (always on, stdlib regexes): JWT, ``sk-`` / ``ghp_`` tokens, PEM
private keys -> ``<REDACTED_SECRET>``; known canaries -> ``CANARY_<sha256[:16]>``.

Level 2 (best effort, Presidio): EMAIL_ADDRESS, PHONE_NUMBER, IBAN_CODE,
CREDIT_CARD -> ``<REDACTED_PII>``. Uses the analyzer REST API when
``PRESIDIO_API_URL`` is set, otherwise a local ``presidio_analyzer`` import.
When neither works the result is ``mode="basic"`` with a warning finding;
redaction never raises because of Presidio.

Findings never contain the redacted values themselves.
"""
from __future__ import annotations

import hashlib
import json
import os
import re
import threading
import time
import urllib.request
from dataclasses import dataclass, field
from typing import Any, Dict, Iterable, List, Optional, Tuple

SECRET_PLACEHOLDER = "<REDACTED_SECRET>"
PII_PLACEHOLDER = "<REDACTED_PII>"
PII_ENTITIES = ("EMAIL_ADDRESS", "PHONE_NUMBER", "IBAN_CODE", "CREDIT_CARD")
MODE_BASIC = "basic"
MODE_FULL = "full"

_SECRET_PATTERNS: Tuple[Tuple[str, "re.Pattern[str]"], ...] = (
    # A truncated preview may hold BEGIN without END: redact to the end of the text.
    ("pem_private_key", re.compile(
        r"-----BEGIN [A-Z ]*PRIVATE KEY-----(?:[\s\S]*?-----END [A-Z ]*PRIVATE KEY-----|[\s\S]*\Z)")),
    ("jwt", re.compile(r"\beyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*")),
    ("sk_token", re.compile(r"\bsk-[a-zA-Z0-9]{30,}")),
    ("github_token", re.compile(r"\bghp_[a-zA-Z0-9]{36,}")),
)

Span = Tuple[str, int, int]


def canary_token(canary: str) -> str:
    return "CANARY_" + hashlib.sha256(canary.encode("utf-8")).hexdigest()[:16]


@dataclass
class RedactionResult:
    text: str
    changed: bool
    mode: str
    findings: List[Dict[str, Any]] = field(default_factory=list)


class Redactor:
    def __init__(self, api_url: Optional[str] = None, *, language: str = "en",
                 timeout: float = 2.0, retry_after: float = 30.0) -> None:
        url = os.environ.get("PRESIDIO_API_URL", "") if api_url is None else api_url
        self.api_url = url.strip() or None
        self.language = language
        self.timeout = timeout
        self.retry_after = retry_after
        self._http_down_until = 0.0
        self._local_engine: Any = None
        self._local_failed = False

    def redact(self, text: str, canaries: Optional[List[str]] = None) -> RedactionResult:
        findings: List[Dict[str, Any]] = []
        out = self._redact_canaries(text, canaries or [], findings)
        out = self._redact_secrets(out, findings)
        out, mode = self._redact_pii(out, findings)
        return RedactionResult(text=out, changed=out != text, mode=mode, findings=findings)

    # -- level 1 ----------------------------------------------------------- #

    @staticmethod
    def _redact_canaries(text: str, canaries: Iterable[str], findings: List[Dict[str, Any]]) -> str:
        # longest first, so a canary that contains another one is replaced whole
        for canary in sorted({c for c in canaries if c}, key=len, reverse=True):
            count = text.count(canary)
            if count:
                token = canary_token(canary)
                text = text.replace(canary, token)
                findings.append({"type": "canary", "kind": "canary", "token": token, "count": count})
        return text

    @staticmethod
    def _redact_secrets(text: str, findings: List[Dict[str, Any]]) -> str:
        for kind, pattern in _SECRET_PATTERNS:
            text, count = pattern.subn(SECRET_PLACEHOLDER, text)
            if count:
                findings.append({"type": "secret", "kind": kind, "count": count})
        return text

    # -- level 2 ----------------------------------------------------------- #

    def _redact_pii(self, text: str, findings: List[Dict[str, Any]]) -> Tuple[str, str]:
        if self.api_url:
            if time.monotonic() < self._http_down_until:
                return text, self._warn(findings, "presidio_http_skipped",
                                        f"previous call failed; retry after {self.retry_after}s")
            try:
                spans = self._analyze_http(text)
            except Exception as exc:  # timeout, refused, HTTP error, bad JSON
                self._http_down_until = time.monotonic() + self.retry_after
                return text, self._warn(findings, "presidio_http_failed", f"{type(exc).__name__}: {exc}")
        else:
            engine = self._local()
            if engine is None:
                return text, self._warn(findings, "presidio_unavailable",
                                        "PRESIDIO_API_URL not set and presidio_analyzer not importable")
            try:
                results = engine.analyze(text=text, entities=list(PII_ENTITIES), language=self.language)
                spans = [(r.entity_type, r.start, r.end) for r in results]
            except Exception as exc:
                return text, self._warn(findings, "presidio_local_failed", f"{type(exc).__name__}: {exc}")
        return self._apply_spans(text, spans, findings), MODE_FULL

    def _analyze_http(self, text: str) -> List[Span]:
        body = json.dumps({"text": text, "language": self.language, "entities": list(PII_ENTITIES)}).encode("utf-8")
        request = urllib.request.Request(self.api_url, data=body, method="POST",
                                         headers={"Content-Type": "application/json"})
        box: Dict[str, Any] = {}

        def call() -> None:
            try:
                with urllib.request.urlopen(request, timeout=self.timeout) as resp:
                    box["value"] = json.loads(resp.read().decode("utf-8"))
            except Exception as exc:
                box["error"] = exc

        # urlopen's timeout applies per resolved address (localhost -> ::1, 127.0.0.1);
        # the join bounds the whole call.
        worker = threading.Thread(target=call, name="presidio-http", daemon=True)
        worker.start()
        worker.join(self.timeout)
        if worker.is_alive():
            raise TimeoutError(f"no answer within {self.timeout}s")
        if "error" in box:
            raise box["error"]
        value = box.get("value")
        if not isinstance(value, list):
            raise ValueError("analyzer response is not a list of results")
        return [(r.get("entity_type"), r.get("start"), r.get("end")) for r in value if isinstance(r, dict)]

    def _local(self) -> Any:
        if self._local_engine is None and not self._local_failed:
            try:
                from presidio_analyzer import AnalyzerEngine
                self._local_engine = AnalyzerEngine()
            except Exception:
                self._local_failed = True
        return self._local_engine

    @staticmethod
    def _apply_spans(text: str, spans: List[Span], findings: List[Dict[str, Any]]) -> str:
        valid = sorted((s, e, kind) for kind, s, e in spans
                       if kind in PII_ENTITIES and isinstance(s, int) and isinstance(e, int) and 0 <= s < e <= len(text))
        merged: List[List[Any]] = []
        for start, end, kind in valid:
            if merged and start < merged[-1][1]:
                merged[-1][1] = max(merged[-1][1], end)
            else:
                merged.append([start, end, kind])
        counts: Dict[str, int] = {}
        for start, end, kind in reversed(merged):
            text = text[:start] + PII_PLACEHOLDER + text[end:]
            counts[kind] = counts.get(kind, 0) + 1
        for kind in sorted(counts):
            findings.append({"type": "pii", "kind": kind, "count": counts[kind]})
        return text

    @staticmethod
    def _warn(findings: List[Dict[str, Any]], kind: str, detail: str) -> str:
        findings.append({"type": "warning", "kind": kind, "detail": detail})
        return MODE_BASIC
