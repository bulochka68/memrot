"""Controlled-validation runner.

Separates *execution* from *control outcome* (TZ §12.2):

  execution_status : completed | error | timeout | skipped
  error_class      : authorization_refusal | schema_error | unknown_tool | transport_error | timeout | tool_error
  control_outcome  : PASS | FAIL | INCONCLUSIVE | NOT_EVALUATED | NOT_APPLICABLE

Outcome rules:
  * allowed expected, allowed effect confirmed              -> PASS
  * denied expected, policy refusal and no effect           -> PASS
  * denied expected, forbidden effect *observed*            -> FAIL
  * allowed expected, refusal not justified by policy       -> FAIL (functional case)
  * schema error / unknown tool / timeout / transport error -> INCONCLUSIVE
  * result returned but the effect cannot be observed       -> INCONCLUSIVE (no effect = no violation claim)
"Blocked" is an observation, never a universal safety verdict; a refusal for
an invalid token says nothing about object-level authorization.
"""
from __future__ import annotations

import os
import re
import time
from typing import Any, Dict, List, Optional, Tuple

from ..models import (Applicability, AuditDocument, ClaimStatus, Confidence, ControlCaseResult, ControlOutcome,
                      ErrorClass, ExecutionStatus, Finding, Method, RemediationPriority, RunMode, Severity, SourceType)
from ..evidence import EvidenceStore, bound_fragment
from ..discovery.introspector import Introspector, MCPError
from .isolation import IsolationGuard, SandboxViolation
from .fixtures import ControlCase, cases_from_fixtures, kind_cases, schema_agrees

_AUTHZ_RX = re.compile(r"(permission denied|not permitted|not allowed|forbidden|unauthori[sz]ed|access denied|denied|"
                       r"outside (the )?(allowed|root)|outside root|401|403|доступ запрещ|отказано|не разрешен)", re.I)
_UNKNOWN_TOOL_RX = re.compile(r"(unknown tool|tool not found|no such tool|method not found|unknown method)", re.I)
_SCHEMA_RX = re.compile(r"(invalid (params|argument|arguments|input)|validation error|missing (required )?(argument|param|field)|"
                        r"unexpected (keyword|argument)|schema)", re.I)


def _is_error(result: dict) -> bool:
    return bool(result.get("isError")) or result.get("is_error") is True


def _text_of(result: dict) -> str:
    parts = []
    for c in result.get("content") or []:
        if isinstance(c, dict) and c.get("type") == "text":
            parts.append(str(c.get("text", "")))
    if not parts and result:
        parts.append(str(result))
    return "\n".join(parts)


def classify_error(exc: Optional[BaseException], result: Optional[dict]) -> ErrorClass:
    if isinstance(exc, TimeoutError):
        return ErrorClass.TIMEOUT
    if isinstance(exc, MCPError):
        code = exc.code
        msg = str(exc)
        if code == -32602 or _SCHEMA_RX.search(msg):
            return ErrorClass.SCHEMA_ERROR
        if code == -32601 or _UNKNOWN_TOOL_RX.search(msg):
            return ErrorClass.UNKNOWN_TOOL
        if _AUTHZ_RX.search(msg) or code in (401, 403):
            return ErrorClass.AUTHORIZATION_REFUSAL
        return ErrorClass.TRANSPORT_ERROR if code is None or code < -32000 else ErrorClass.TOOL_ERROR
    if isinstance(exc, OSError):
        return ErrorClass.TRANSPORT_ERROR
    if exc is not None:
        return ErrorClass.TRANSPORT_ERROR
    if result is not None and _is_error(result):
        text = _text_of(result)
        if _UNKNOWN_TOOL_RX.search(text):
            return ErrorClass.UNKNOWN_TOOL
        if _SCHEMA_RX.search(text):
            return ErrorClass.SCHEMA_ERROR
        if _AUTHZ_RX.search(text):
            return ErrorClass.AUTHORIZATION_REFUSAL
        return ErrorClass.TOOL_ERROR
    return ErrorClass.NONE


def observe_effect(check: Dict[str, Any], result: Optional[dict], sink: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    """Observe the effect independently of the response text where possible."""
    kind = check.get("kind", "none")
    text = _text_of(result or {})
    if kind == "none":
        return {"kind": kind, "observed": None, "details": "no effect observation defined for this case"}
    if kind == "file_exists":
        p = check.get("path", "")
        exists = os.path.isfile(p)
        needle_ok = True
        if exists and check.get("needle"):
            try:
                with open(p, "r", encoding="utf-8", errors="replace") as fh:
                    needle_ok = check["needle"] in fh.read()
            except OSError:
                needle_ok = False
        return {"kind": kind, "observed": bool(exists and needle_ok), "details": f"{p} exists={exists} content_ok={needle_ok}"}
    if kind == "file_absent":
        p = check.get("path", "")
        exists = os.path.exists(p)
        return {"kind": kind, "observed": (not exists), "details": f"{p} exists={exists}", "forbidden_effect": exists}
    if kind == "response_contains":
        ok = bool(check.get("needle")) and check["needle"] in text
        return {"kind": kind, "observed": ok, "details": "needle found in response" if ok else "needle not in response",
                "limitation": "response text is the only observation; the state change itself is not independently confirmed"}
    if kind == "response_not_contains":
        present = bool(check.get("needle")) and check["needle"] in text
        return {"kind": kind, "observed": (not present), "forbidden_effect": present,
                "details": "forbidden content present in response" if present else "forbidden content absent"}
    if kind == "sink_received":
        if sink is None:
            return {"kind": kind, "observed": None, "details": "no local sink fixture available; external effect not observable"}
        got = check.get("needle") in (sink.get("received") or [])
        return {"kind": kind, "observed": got, "forbidden_effect": got, "details": f"sink received={got}"}
    return {"kind": kind, "observed": None, "details": f"unsupported effect check {kind!r}"}


def decide(case: ControlCase, exec_status: ExecutionStatus, err: ErrorClass, effect: Dict[str, Any]) -> Tuple[ControlOutcome, str]:
    if exec_status in (ExecutionStatus.TIMEOUT, ExecutionStatus.ERROR) and err in (
            ErrorClass.TIMEOUT, ErrorClass.TRANSPORT_ERROR, ErrorClass.SCHEMA_ERROR, ErrorClass.UNKNOWN_TOOL):
        return ControlOutcome.INCONCLUSIVE, f"{err.value}: the control under test was not reached"
    if case.expected == "denied":
        if effect.get("forbidden_effect") is True:
            return ControlOutcome.FAIL, "forbidden effect observed"
        if err == ErrorClass.AUTHORIZATION_REFUSAL:
            if effect.get("observed") is False and effect.get("kind") not in ("none",):
                return ControlOutcome.INCONCLUSIVE, "refusal returned but the effect check indicates a change"
            return ControlOutcome.PASS, "policy refusal observed and no forbidden effect"
        if err == ErrorClass.TOOL_ERROR:
            if effect.get("observed") is True:
                return ControlOutcome.PASS, "tool error and independent check shows no effect"
            return ControlOutcome.INCONCLUSIVE, "tool error that is not a policy refusal; effect unknown"
        # completed without error
        if effect.get("kind") == "none" or effect.get("observed") is None:
            return ControlOutcome.INCONCLUSIVE, "call succeeded but the forbidden effect could not be observed; no violation is claimed"
        if effect.get("observed") is True:
            return ControlOutcome.PASS, "call returned but the independent check shows no forbidden effect"
        return ControlOutcome.FAIL, "forbidden effect observed"
    # expected allowed (functional control case)
    if err == ErrorClass.AUTHORIZATION_REFUSAL:
        return ControlOutcome.FAIL, "allowed operation refused: mass blocking is not a quality control"
    if err == ErrorClass.TOOL_ERROR:
        return ControlOutcome.INCONCLUSIVE, "tool error on an allowed operation"
    if effect.get("observed") is True:
        return ControlOutcome.PASS, "allowed effect confirmed"
    if effect.get("observed") is None:
        return ControlOutcome.INCONCLUSIVE, "call returned but the allowed effect was not independently observed"
    return ControlOutcome.FAIL, "allowed operation did not produce the expected effect"


def _server_root(server) -> Optional[str]:
    acc = server.effective_access or {}
    allowed = ((acc.get("policy_expected") or {}).get("paths_allowed")) or ((acc.get("inferred") or {}).get("paths_allowed")) or []
    if allowed:
        return allowed[0].replace("/**", "").rstrip("/") or None
    return None


def _run_case(client: Introspector, case: ControlCase, tool, sink: Optional[Dict[str, Any]]) -> ControlCaseResult:
    reasons = schema_agrees(tool, case.arguments)
    if reasons:
        return ControlCaseResult(
            id=case.id, name=case.name, server=case.server, tool=case.tool, rule_id=case.rule_id or "",
            expected=case.expected, execution_status=ExecutionStatus.SKIPPED, control_outcome=ControlOutcome.INCONCLUSIVE,
            applicability=Applicability.UNKNOWN, error_class=ErrorClass.UNKNOWN_TOOL if tool is None else ErrorClass.SCHEMA_ERROR,
            expected_invariant=case.expected_invariant, boundary_ref=case.boundary_ref,
            limitations=["contract mismatch: " + "; ".join(reasons), "the case was not executed; no PASS is derived from a mismatched schema"],
            details="schema disagreement", arguments=case.arguments, prepared_by=case.prepared_by,
        )
    raw: Optional[dict] = None
    exc: Optional[BaseException] = None
    started = time.time()
    try:
        raw = client.call_tool(case.tool, case.arguments)
        status = ExecutionStatus.COMPLETED
    except TimeoutError as e:
        exc, status = e, ExecutionStatus.TIMEOUT
    except (MCPError, OSError) as e:
        exc, status = e, ExecutionStatus.ERROR
    err = classify_error(exc, raw)
    if status == ExecutionStatus.COMPLETED and err != ErrorClass.NONE:
        status = ExecutionStatus.COMPLETED     # the server answered; the answer is an error of class `err`
    effect = observe_effect(case.effect_check, raw, sink)
    outcome, interp = decide(case, status, err, effect)
    limitations = []
    if effect.get("limitation"):
        limitations.append(effect["limitation"])
    if case.prepared_by == "fixture_admin":
        limitations.append("record/state prepared by the fixture administrator: confirms later stages only, not that a user session can create it")
    if err == ErrorClass.AUTHORIZATION_REFUSAL and case.expected == "denied":
        limitations.append("a refusal is an observation for this principal and object only; not a universal safety verdict")
    return ControlCaseResult(
        id=case.id, name=case.name, server=case.server, tool=case.tool, rule_id=case.rule_id or "",
        expected=case.expected, execution_status=status, control_outcome=outcome, error_class=err,
        observed_effect=effect, expected_invariant=case.expected_invariant, boundary_ref=case.boundary_ref,
        evaluated_boundary_refs=[case.boundary_ref] if case.boundary_ref and outcome in (ControlOutcome.PASS, ControlOutcome.FAIL) else [],
        limitations=limitations, details=f"{interp}; {str(exc) if exc else 'ok'}", arguments=case.arguments,
        raw_summary=bound_fragment(str(raw)[:400] if raw is not None else str(exc), 400) or "",
        prepared_by=case.prepared_by, fixture={"started_at": started, "finished_at": time.time()},
    )


def run_controlled_validation(doc: AuditDocument, guard: IsolationGuard, store: Optional[EvidenceStore] = None, *,
                              timeout: float = 20.0, cwd: Optional[str] = None,
                              sink: Optional[Dict[str, Any]] = None, use_kind_catalogue: bool = True) -> None:
    """Run registered control cases against live servers.  Refuses without the sandbox declaration."""
    store = store or EvidenceStore(doc)
    try:
        guard.ensure_sandbox()
    except SandboxViolation as e:
        doc.meta["isolation"] = {"declared": False, "error": str(e)}
        doc.limitations.append(f"controlled validation refused: {e}")
        return
    fx = doc.meta.get("control_fixtures") or {}
    iso = IsolationGuard.technical_evidence(fx.get("isolation"))
    doc.meta["isolation"] = {"declared": True, "declaration": guard.declaration(), "technical": iso,
                             "evidence_refs": [fx["evidence_ref"]] if fx.get("evidence_ref") else []}
    base_vars = {"canary": guard.canary_token, "sinkhole": guard.sinkhole}
    results: List[ControlCaseResult] = []
    deadline = time.monotonic() + guard.max_seconds
    count = 0
    for server in doc.servers:
        if server.transport == "stdio" and not server.command:
            continue
        vars_ = dict(base_vars)
        root = (fx.get("roots") or {}).get(server.name) or _server_root(server)
        if root:
            vars_["root"] = root
        registered = cases_from_fixtures([c for c in (fx.get("cases") or []) if c.get("server") == server.name], vars_)
        cases = list(registered)
        if use_kind_catalogue and not cases:
            cases = kind_cases(server, vars_, root=root)
        if not cases:
            continue
        cases = [c for c in cases if guard.allow_destructive or not c.destructive]
        skipped = [c for c in (registered or (kind_cases(server, vars_, root=root) if use_kind_catalogue else [])) if c.destructive and not guard.allow_destructive]
        for c in skipped:
            results.append(ControlCaseResult(id=c.id, name=c.name, server=c.server, tool=c.tool, rule_id=c.rule_id or "",
                                             expected=c.expected, execution_status=ExecutionStatus.SKIPPED,
                                             control_outcome=ControlOutcome.NOT_EVALUATED, details="destructive case skipped (allow_destructive=False)",
                                             limitations=["destructive case not executed"], arguments=c.arguments))
        remaining = list(cases)
        while remaining:
            try:
                with Introspector(server, timeout=timeout, cwd=cwd) as client:
                    client.initialize()
                    by_name = {t.name: t for t in server.tools}
                    while remaining:
                        case = remaining.pop(0)
                        if count >= guard.max_cases or time.monotonic() > deadline:
                            results.append(ControlCaseResult(id=case.id, name=case.name, server=case.server, tool=case.tool,
                                                             rule_id=case.rule_id or "", expected=case.expected,
                                                             execution_status=ExecutionStatus.SKIPPED, control_outcome=ControlOutcome.NOT_EVALUATED,
                                                             details="resource budget exhausted", arguments=case.arguments))
                            continue
                        guard.note(f"case {case.id} -> {server.name}/{case.tool}")
                        res = _run_case(client, case, by_name.get(case.tool), sink)
                        count += 1
                        _record_case(doc, store, server, case, res)
                        results.append(res)
                        if res.execution_status == ExecutionStatus.TIMEOUT:
                            # the transport state is unknown after a timeout: reconnect for the remaining cases
                            res.limitations.append("connection reset after timeout; later cases ran on a fresh connection")
                            break
            except (MCPError, TimeoutError, OSError) as e:
                for case in remaining:
                    results.append(ControlCaseResult(id=case.id, name=case.name, server=case.server, tool=case.tool,
                                                     rule_id=case.rule_id or "", expected=case.expected,
                                                     execution_status=ExecutionStatus.ERROR, control_outcome=ControlOutcome.INCONCLUSIVE,
                                                     error_class=classify_error(e, None), details=f"connection failed: {e}",
                                                     limitations=["server unreachable; no boundary was evaluated"], arguments=case.arguments))
                remaining = []
    doc.tests = results
    _attach_observed_access(doc)


def _record_case(doc: AuditDocument, store: EvidenceStore, server, case: ControlCase, res: ControlCaseResult) -> None:
    ev = store.add(SourceType.FIXTURE_OBSERVATION, Method.CONTROLLED_VALIDATION,
                   {"case": case.id, "server": server.name, "tool": case.tool},
                   summary=f"{case.id}: {res.execution_status.value}/{res.error_class.value} -> {res.control_outcome.value}",
                   fragment=res.raw_summary, captured_at=res.fixture.get("finished_at"),
                   scope={"principal": doc.meta.get("validation_identity"), "environment": "fixture"},
                   limitations=list(res.limitations))
    res.evidence_refs.append(ev.evidence_id)
    claim = store.claim(f"CL-CASE-{case.id}", f"{case.id}: {res.details}",
                        ClaimStatus.RUNTIME_SUPPORTED if res.execution_status == ExecutionStatus.COMPLETED
                        else ClaimStatus.INCONCLUSIVE,
                        evidence_refs=[ev.evidence_id], confidence=Confidence.MEDIUM,
                        explanation="single fixture run; repeat runs needed for stochastic behaviour",
                        limitations=list(res.limitations), rule_refs=[case.rule_id] if case.rule_id else [],
                        scope={"server": server.name, "tool": case.tool, "environment": "fixture"},
                        source_type=SourceType.FIXTURE_OBSERVATION, method=Method.CONTROLLED_VALIDATION)
    res.claim_refs.append(claim.claim_id)
    if res.control_outcome == ControlOutcome.FAIL and case.expected == "denied":
        doc.add_finding(Finding(
            code="CONTROL_VIOLATION_OBSERVED", title=f"Forbidden effect observed: {case.name}",
            description=f"{case.expected_invariant}; observed: {res.observed_effect.get('details')}",
            rule_id=case.rule_id or "", plane="behavioral", verification_status=ClaimStatus.RUNTIME_SUPPORTED,
            severity=Severity.CRITICAL, severity_rationale="a claimed boundary does not hold in the fixture",
            boundary_refs=[case.boundary_ref] if case.boundary_ref else [], claim_refs=[claim.claim_id],
            evidence_refs=[ev.evidence_id], observed_effect=res.observed_effect.get("details"),
            server=server.name, tool=case.tool, scope={"environment": "fixture", "case": case.id},
            remediation="enforce the boundary at the server; add the case to the regression fixture",
            closure_criterion="the same case yields PASS (refusal, no effect) on a new build",
            limitations=list(res.limitations), remediation_priority=RemediationPriority.P0,
        ))


def _attach_observed_access(doc: AuditDocument) -> None:
    for res in doc.tests:
        s = doc.server(res.server)
        if not s:
            continue
        obs = s.effective_access.setdefault("observed", {"basis": "controlled validation / trace", "items": []})
        obs.setdefault("items", []).append({
            "case": res.id, "tool": res.tool, "expected": res.expected, "outcome": res.control_outcome.value,
            "execution": res.execution_status.value, "error_class": res.error_class.value,
            "note": "observation for one object and one principal in the fixture; not a scope-wide confirmation",
        })


# legacy name
run_active_verification = run_controlled_validation
