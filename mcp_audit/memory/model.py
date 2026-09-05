"""Normalized memory records, lifecycle stages and W/R/C/B observations.

Rules that shape this module:

* unknown values stay unknown - the adapter never substitutes the current
  user for a missing owner (TZ §8.3);
* content cannot certify its own provenance: a ``trusted=true`` flag coming
  from an LLM is not evidence;
* a write, a retrieval, a context inclusion and a behavioural effect are
  four different observations, each with its own status (TZ §12.3);
* ``not_observed`` is only allowed when the event kind is actually covered
  by the trace; otherwise the stage is ``unknown``.
"""
from __future__ import annotations

from dataclasses import dataclass, field, fields
from typing import Any, Dict, Iterable, List, Optional

from ..models import MEMORY_STAGES, StageObservation, plain

LIFECYCLE_STAGES = (
    "acquisition", "derivation", "candidate_extraction", "write_authorization", "publication",
    "storage", "retrieval", "context_assembly", "use", "revocation",
)

MEMORY_RECORD_FIELDS: Dict[str, List[str]] = {
    "identifiers": ["memory_id", "version", "memory_type", "store_ref"],
    "ownership": ["tenant_ref", "subject_ref", "agent_ref", "session_ref"],
    "access": ["read_audience_ref", "write_policy_ref", "authority"],
    "authorship": ["origin_actor_ref", "writer_principal_ref", "publisher_ref"],
    "provenance": ["source_event_refs", "derived_from", "transformation_ref", "lineage_completeness"],
    "review": ["review_state", "approval_ref", "policy_revision"],
    "lifecycle": ["created_at", "expires_at", "revoked_at", "supersedes_ref"],
    "content": ["content_digest", "content_ref", "content_preview"],
}

# fields whose value must come from a trusted party, never from the record body itself
AUTHORITY_FIELDS = ("authority", "read_audience_ref", "write_policy_ref", "publisher_ref", "review_state", "approval_ref")

_STAGE_EVENT = {"W": "write", "R": "retrieve", "C": "context_include", "B": "behavior"}


def normalize_record(raw: Dict[str, Any], *, store_ref: Optional[str] = None,
                     field_map: Optional[Dict[str, str]] = None) -> Dict[str, Any]:
    """Map a store-specific record onto the normalized shape.

    ``field_map`` maps normalized names to raw keys (``{"subject_ref": "user_id"}``).
    Missing values are recorded as ``None`` together with ``unknown_fields``.
    Self-asserted authority metadata found *inside the content* is kept apart
    under ``self_asserted`` and never promoted.
    """
    field_map = dict(field_map or {})
    out: Dict[str, Any] = {"unknown_fields": [], "self_asserted": {}, "extensions": {}}
    for group, names in MEMORY_RECORD_FIELDS.items():
        for name in names:
            key = field_map.get(name, name)
            if key in raw:
                out[name] = raw[key]
            else:
                out[name] = None
                out["unknown_fields"].append(name)
    if store_ref and not out.get("store_ref"):
        out["store_ref"] = store_ref
        out["unknown_fields"] = [f for f in out["unknown_fields"] if f != "store_ref"]
    content = raw.get(field_map.get("content", "content"))
    if isinstance(content, dict):
        for f in AUTHORITY_FIELDS + ("trusted", "verified", "owner", "signature"):
            if f in content:
                out["self_asserted"][f] = content[f]
    for k, v in raw.items():
        if k not in field_map.values() and k not in out and k != "content":
            out["extensions"][k] = v
    return out


def lineage_completeness(record: Dict[str, Any]) -> str:
    parents = record.get("derived_from") or []
    src = record.get("source_event_refs") or []
    declared = record.get("lineage_completeness")
    if declared in ("complete", "partial", "unknown", "lost"):
        return declared
    if parents or src:
        return "partial"
    return "unknown"


@dataclass
class MemoryCaseObservation:
    case_id: str
    memory_id: Optional[str]
    subject: Optional[str]
    stages: Dict[str, StageObservation] = field(default_factory=lambda: {s: StageObservation.NOT_EVALUATED for s in MEMORY_STAGES})
    event_refs: Dict[str, List[str]] = field(default_factory=dict)
    limitations: List[str] = field(default_factory=list)
    prepared_by: Optional[str] = None
    expected: Dict[str, Any] = field(default_factory=dict)
    conclusion: str = ""

    def to_dict(self) -> Dict[str, Any]:
        d = plain({f.name: getattr(self, f.name) for f in fields(self)})
        d["stages"] = {k: v.value for k, v in self.stages.items()}
        return d


def _events_for(events: Iterable[Dict[str, Any]], memory_id: Optional[str], kind: str,
                subject: Optional[str] = None) -> List[Dict[str, Any]]:
    out = []
    for e in events:
        mem = e.get("memory") or {}
        if mem.get("operation") != kind:
            continue
        if memory_id and mem.get("memory_id") != memory_id:
            continue
        if subject and e.get("principal") not in (None, subject):
            continue
        out.append(e)
    return out


def observe_cases(cases: Iterable[Dict[str, Any]], events: List[Dict[str, Any]],
                  coverage: Dict[str, bool]) -> List[MemoryCaseObservation]:
    """Evaluate W/R/C/B for each case against the trace events.

    ``coverage`` says which event kinds the trace can contain
    (``{"write": True, "retrieve": True, "context_include": False, "behavior": False}``).
    A stage whose kind is not covered is ``unknown``, not ``not_observed``.
    """
    out: List[MemoryCaseObservation] = []
    for case in cases:
        obs = MemoryCaseObservation(
            case_id=case.get("case_id") or case.get("id") or "case",
            memory_id=case.get("memory_id"), subject=case.get("subject"),
            prepared_by=case.get("prepared_by"), expected=dict(case.get("expected") or {}),
        )
        for stage in MEMORY_STAGES:
            kind = _STAGE_EVENT[stage]
            if not case.get("evaluate", {}).get(stage, True):
                obs.stages[stage] = StageObservation.NOT_EVALUATED
                continue
            if not coverage.get(kind):
                obs.stages[stage] = StageObservation.UNKNOWN
                obs.limitations.append(f"stage {stage}: trace does not cover '{kind}' events; absence is not evidence")
                continue
            hits = _events_for(events, obs.memory_id, kind, obs.subject if stage in ("R", "C") else None)
            if stage == "C":
                hits = [h for h in hits if (h.get("memory") or {}).get("included_in_context") is not False]
            if stage == "B":
                effect = case.get("effect_ref")
                hits = [h for h in hits if not effect or (h.get("observation") or {}).get("effect_id") == effect]
                hits = [h for h in hits if (h.get("observation") or {}).get("observed") is True]
            obs.stages[stage] = StageObservation.OBSERVED if hits else StageObservation.NOT_OBSERVED
            obs.event_refs[stage] = [h.get("event_id") for h in hits if h.get("event_id")]
        if obs.prepared_by == "fixture_admin":
            obs.limitations.append(
                "record was prepared directly by the fixture administrator: later stages (R/C/B) are "
                "evaluated, but this does not show that a user session can create such a record")
        if obs.stages.get("B") == StageObservation.OBSERVED:
            obs.limitations.append("behaviour observed; causal attribution to this record needs a controlled "
                                   "comparison with a clean fixture state")
        obs.conclusion = _conclude(obs)
        out.append(obs)
    return out


def _conclude(obs: MemoryCaseObservation) -> str:
    s = obs.stages
    if s.get("W") == StageObservation.OBSERVED and s.get("C") == StageObservation.NOT_OBSERVED:
        return "written but not included in context in the observed runs; no model influence is claimed"
    if s.get("C") == StageObservation.UNKNOWN:
        return "context inclusion unobservable; neither inclusion nor a working control is claimed"
    if s.get("C") == StageObservation.OBSERVED and s.get("B") != StageObservation.OBSERVED:
        return "included in context; behavioural effect not observed or not evaluated"
    if s.get("B") == StageObservation.OBSERVED:
        return "behavioural effect observed (causality not established by this observation alone)"
    return "see stages"
