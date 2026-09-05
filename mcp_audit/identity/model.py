"""Principals, resources and per-hop access transitions.

For every hop the audit keeps a separate record:
``input identity -> executing service -> operation -> resource -> policy decision -> next service``.
A refusal on the entry API says nothing about the backend the request never
reached (TZ §9).
"""
from __future__ import annotations

from dataclasses import dataclass, field, fields
from typing import Any, Dict, List, Optional

from ..models import KnowledgeState, Principal, plain


# What each authentication scheme must validate.  Absence of JWT is not a
# failure of AUTH-04: the equivalent requirements of the scheme apply.
AUTH_SCHEME_REQUIREMENTS: Dict[str, List[str]] = {
    "jwt": ["signature", "issuer", "audience", "expiry", "algorithm"],
    "api_key": ["lookup", "revocation", "binding_to_principal"],
    "session": ["session_validation", "expiry", "binding_to_principal"],
    "mtls": ["certificate_chain", "subject_binding"],
    "none": [],
}


@dataclass
class AccessTransition:
    transition_id: str
    input_principal: str
    executing_component: str
    operation: str
    resource: str
    next_component: Optional[str] = None
    policy_decision: str = "unknown"          # enforced | not_enforced | conditional | unknown
    conditions: List[str] = field(default_factory=list)
    enforcement_point: Optional[str] = None
    auth_scheme: str = "unknown"
    delegation: Optional[str] = None          # e.g. token_exchange | service_account | passthrough
    evidence_refs: List[str] = field(default_factory=list)
    knowledge_state: KnowledgeState = KnowledgeState.ASSUMED
    observed: str = "not_observed"            # observed | not_observed | unknown

    def to_dict(self) -> Dict[str, Any]:
        return plain({f.name: getattr(self, f.name) for f in fields(self)})


def build_principals(policy: Dict[str, Any], profile: Dict[str, Any]) -> List[Principal]:
    """Principals come from the policy snapshot first, then the profile; both are
    declarations, so the knowledge state stays ``assumed`` until observed."""
    out: List[Principal] = []
    seen = set()
    for src, state in ((policy.get("principals") or [], KnowledgeState.KNOWN),
                       (profile.get("principals") or [], KnowledgeState.ASSUMED)):
        for p in src:
            pid = p.get("id") or p.get("principal_id")
            if not pid or pid in seen:
                continue
            seen.add(pid)
            out.append(Principal(
                principal_id=pid, type=p.get("type", "unknown"),
                allowed_scope=dict(p.get("allowed_scope") or {}),
                identity_source=p.get("identity_source", "unknown"),
                delegation=list(p.get("delegation") or []),
                knowledge_state=state,
            ))
    return out


def build_transitions(source_facts: Dict[str, Any], policy: Dict[str, Any]) -> List[AccessTransition]:
    """Transitions declared by the profile/source facts (``auth_transitions``)
    are matched against the expected policy (``access_rules``)."""
    out: List[AccessTransition] = []
    for i, t in enumerate(source_facts.get("auth_transitions") or []):
        out.append(AccessTransition(
            transition_id=t.get("id") or f"T-{i + 1}",
            input_principal=t.get("input_principal", "unknown"),
            executing_component=t.get("executing_component", "unknown"),
            operation=t.get("operation", "unknown"),
            resource=t.get("resource", "unknown"),
            next_component=t.get("next_component"),
            policy_decision=t.get("policy_decision", "unknown"),
            conditions=list(t.get("conditions") or []),
            enforcement_point=t.get("enforcement_point"),
            auth_scheme=t.get("auth_scheme", "unknown"),
            delegation=t.get("delegation"),
            evidence_refs=list(t.get("evidence_refs") or []),
            knowledge_state=KnowledgeState(t.get("knowledge_state", "assumed")),
            observed=t.get("observed", "not_observed"),
        ))
    return out


def token_validation_gaps(observed: Dict[str, Any], scheme: str) -> List[str]:
    """Return the checks required by ``scheme`` that the observed validation config does not perform."""
    required = AUTH_SCHEME_REQUIREMENTS.get(scheme, [])
    gaps: List[str] = []
    for req in required:
        val = observed.get(req)
        if val is False:
            gaps.append(req)
        elif val is None:
            gaps.append(f"{req}:unknown")
    return gaps
