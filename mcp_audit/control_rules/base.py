"""Rule contract (TZ §19.1).

Every rule declares id/version, the violated requirement, applicability, the
sources it needs, the allowed evaluation methods, the expected invariant, the
outcome rules, known false positives, limitations and the remediation
criterion.  Rules never contain names of a concrete stand (collections,
tools, ``cus``): those belong to the *profile*.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Callable, Dict, Iterable, List, Optional, Sequence, Tuple

from ..models import (Applicability, AuditDocument, Claim, ClaimStatus, Confidence, ControlOutcome,
                      ControlResult, ExecutionStatus, Finding, Method, RemediationPriority, Severity,
                      SourceType, StageObservation)
from ..evidence import EvidenceStore


@dataclass
class RuleContext:
    doc: AuditDocument
    store: EvidenceStore
    available: set = field(default_factory=set)      # adapter kinds available or partial
    rule: Optional["Rule"] = None
    correlation: Dict[str, Any] = field(default_factory=dict)

    # -- data access -------------------------------------------------------- #
    @property
    def profile(self) -> Dict[str, Any]:
        return self.doc.profile

    @property
    def policy(self) -> Dict[str, Any]:
        return self.doc.policy

    @property
    def facts(self) -> Dict[str, Any]:
        return self.doc.source_facts

    def has(self, kind: str) -> bool:
        return kind in self.available

    def flows(self, kind: Optional[str] = None, **attrs: Any) -> List[Dict[str, Any]]:
        out = []
        for f in self.facts.get("flows") or []:
            if kind and f.get("kind") != kind:
                continue
            if all(f.get(k) == v for k, v in attrs.items()):
                out.append(f)
        return out

    def memory_type_policy(self, memory_type: Optional[str]) -> Dict[str, Any]:
        for mt in ((self.policy.get("memory_policy") or {}).get("memory_types") or []):
            if mt.get("type") == memory_type:
                return mt
        return {}

    def memory_types_declared(self) -> List[Dict[str, Any]]:
        out: List[Dict[str, Any]] = []
        for st in self.profile.get("memory_stores") or []:
            for mt in st.get("memory_types") or []:
                out.append({**mt, "store": st.get("component_id")})
        for mt in ((self.policy.get("memory_policy") or {}).get("memory_types") or []):
            if not any(o.get("type") == mt.get("type") for o in out):
                out.append(dict(mt))
        return out

    def chain_state(self, rule_id: str) -> List[Dict[str, Any]]:
        return [c for c in (self.correlation.get("chains") or []) if rule_id in (c.get("rule_refs") or [])]

    # -- claims / findings -------------------------------------------------- #
    def claim(self, claim_id: str, statement: str, status: ClaimStatus, *, evidence_refs: Iterable[str] = (),
              confidence: Confidence = Confidence.UNKNOWN, explanation: str = "",
              limitations: Iterable[str] = (), component_refs: Iterable[str] = (),
              scope: Optional[Dict[str, Any]] = None, source_type: Optional[SourceType] = None,
              method: Optional[Method] = None) -> Claim:
        refs = [r for r in evidence_refs if r]
        if not refs and status in (ClaimStatus.STATIC_SUPPORTED, ClaimStatus.RUNTIME_SUPPORTED):
            status = ClaimStatus.HYPOTHESIS
            limitations = list(limitations) + ["no evidence reference attached; downgraded to hypothesis"]
        return self.store.claim(claim_id, statement, status, evidence_refs=refs, confidence=confidence,
                                explanation=explanation, limitations=limitations,
                                rule_refs=[self.rule.rule_id] if self.rule else [],
                                component_refs=component_refs, scope=scope, source_type=source_type, method=method)

    def finding(self, code: str, title: str, description: str, *, status: ClaimStatus,
                severity: Optional[Severity] = None, potential_severity: Optional[Severity] = None,
                rationale: str = "", root_cause: str = "", component_refs: Iterable[str] = (),
                boundary_refs: Iterable[str] = (), claim_refs: Iterable[str] = (),
                evidence_refs: Iterable[str] = (), observed_effect: Optional[str] = None,
                potential_effect: Optional[str] = None, remediation: str = "", closure_criterion: str = "",
                priority: Optional[RemediationPriority] = None, limitations: Iterable[str] = (),
                unconfirmed: Iterable[str] = (), preconditions: Iterable[str] = (), scope: Optional[Dict[str, Any]] = None,
                memory_stages: Optional[Dict[str, StageObservation]] = None, plane: Optional[str] = None,
                server: Optional[str] = None, tool: Optional[str] = None, evidence: Optional[Dict[str, Any]] = None,
                taxonomy: Iterable[str] = (), owner: Optional[str] = None) -> Finding:
        r = self.rule
        confirmed = status in (ClaimStatus.STATIC_SUPPORTED, ClaimStatus.RUNTIME_SUPPORTED)
        f = Finding(
            code=code, title=title, description=description, rule_id=r.rule_id if r else "", plane=plane or (r.domain if r else "correlation"),
            verification_status=status,
            severity=severity if confirmed else None,
            potential_severity=potential_severity or (severity if not confirmed else None),
            severity_rationale=rationale, rule_version=r.version if r else "", root_cause=root_cause,
            requirement=r.requirement if r else "", preconditions=list(preconditions),
            expected_invariant=r.expected_invariant if r else "",
            component_refs=list(component_refs), boundary_refs=list(boundary_refs), scope=dict(scope or {}),
            claim_refs=list(claim_refs), evidence_refs=[e for e in evidence_refs if e],
            observed_effect=observed_effect, potential_effect=potential_effect,
            remediation=remediation or (r.remediation_criterion if r else ""), remediation_owner=owner,
            remediation_priority=priority, closure_criterion=closure_criterion or (r.remediation_criterion if r else ""),
            limitations=list(limitations) + (list(r.limitations) if r else []), unconfirmed=list(unconfirmed),
            memory_stages=dict(memory_stages or {}), server=server, tool=tool, evidence=dict(evidence or {}),
            taxonomy=list(taxonomy),
        )
        return self.doc.add_finding(f)


@dataclass
class RuleEvaluation:
    outcome: ControlOutcome
    execution_status: ExecutionStatus = ExecutionStatus.COMPLETED
    observed_effect: Optional[str] = None
    interpretation: str = ""
    claim_refs: List[str] = field(default_factory=list)
    evidence_refs: List[str] = field(default_factory=list)
    finding_refs: List[str] = field(default_factory=list)
    limitations: List[str] = field(default_factory=list)
    boundary_refs: List[str] = field(default_factory=list)
    component_refs: List[str] = field(default_factory=list)
    method: Optional[Method] = None
    conditions: Dict[str, Any] = field(default_factory=dict)
    case_refs: List[str] = field(default_factory=list)


@dataclass
class Rule:
    rule_id: str
    version: str
    title: str
    requirement: str
    criterion: str
    domain: str                                   # memory | identity | infrastructure | tools | egress | inventory
    required_sources: List[List[str]]             # alternatives; any one full set is enough
    methods: List[Method]
    expected_invariant: str
    evaluate: Callable[[RuleContext], RuleEvaluation]
    applicability: Optional[Callable[[RuleContext], Tuple[Applicability, str]]] = None
    known_false_positives: List[str] = field(default_factory=list)
    limitations: List[str] = field(default_factory=list)
    remediation_criterion: str = ""
    external_refs: List[Dict[str, str]] = field(default_factory=list)
    stage: str = "B"
    default_priority: RemediationPriority = RemediationPriority.P1

    def missing_sources(self, available: set) -> List[str]:
        """Return the missing kinds for the *closest* alternative (empty = satisfiable)."""
        best: Optional[List[str]] = None
        for alt in self.required_sources:
            miss = [k for k in alt if k not in available]
            if not miss:
                return []
            if best is None or len(miss) < len(best):
                best = miss
        return best or []

    def to_dict(self) -> Dict[str, Any]:
        return {
            "rule_id": self.rule_id, "version": self.version, "title": self.title, "requirement": self.requirement,
            "criterion": self.criterion, "domain": self.domain, "required_sources": self.required_sources,
            "methods": [m.value for m in self.methods], "expected_invariant": self.expected_invariant,
            "known_false_positives": self.known_false_positives, "limitations": self.limitations,
            "remediation_criterion": self.remediation_criterion, "external_refs": self.external_refs,
            "stage": self.stage, "default_priority": self.default_priority.value,
        }


def not_evaluated(reason: str, missing: Sequence[str] = ()) -> RuleEvaluation:
    return RuleEvaluation(outcome=ControlOutcome.NOT_EVALUATED, execution_status=ExecutionStatus.SKIPPED,
                          interpretation=reason, limitations=[reason] + [f"missing source: {m}" for m in missing])


def inconclusive(reason: str, **kw: Any) -> RuleEvaluation:
    return RuleEvaluation(outcome=ControlOutcome.INCONCLUSIVE, interpretation=reason,
                          limitations=[reason] + list(kw.pop("limitations", [])), **kw)


def worst(outcomes: Iterable[ControlOutcome]) -> ControlOutcome:
    order = [ControlOutcome.NOT_APPLICABLE, ControlOutcome.NOT_EVALUATED, ControlOutcome.PASS,
             ControlOutcome.INCONCLUSIVE, ControlOutcome.FAIL]
    res = ControlOutcome.NOT_EVALUATED
    seen = list(outcomes)
    if not seen:
        return res
    return max(seen, key=lambda o: order.index(o))


def status_from(items: Iterable[Dict[str, Any]]) -> ClaimStatus:
    """Claim status for a set of source-verified facts."""
    statuses = [i.get("status") for i in items]
    if not statuses:
        return ClaimStatus.HYPOTHESIS
    if any(s == "contradicted" for s in statuses):
        return ClaimStatus.CONTRADICTED
    if all(s == "static_supported" for s in statuses):
        return ClaimStatus.STATIC_SUPPORTED
    if all(s == "runtime_supported" for s in statuses):
        return ClaimStatus.RUNTIME_SUPPORTED
    return ClaimStatus.INCONCLUSIVE


def refs_of(items: Iterable[Dict[str, Any]]) -> List[str]:
    out: List[str] = []
    for i in items:
        for r in i.get("evidence_refs") or []:
            if r not in out:
                out.append(r)
    return out
