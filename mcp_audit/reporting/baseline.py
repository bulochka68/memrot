"""Baseline store and drift comparison v2 (TZ §17).

A baseline is a snapshot with its identity: target, build, environment, role
used for discovery, schema and canonicalization versions, rule versions,
plus digests of policy, service rights, memory schema, retrieval/egress
config and inventory completeness.  Comparison first checks *compatibility*;
differences are classified (added / removed / definition_changed /
policy_changed / access_changed / runtime_config_changed / coverage_changed /
comparison_inconclusive) and carry an ``approval_state``.  A changed hash is
drift; malice and impact need separate evidence.
"""
from __future__ import annotations

import json
import time
from typing import Any, Dict, List, Optional

from .. import AUDIT_SCHEMA_VERSION, RULESET_VERSION
from ..models import (ApprovalState, AuditDocument, ChangeKind, ClaimStatus, Confidence, Method, SourceType, digest as _digest)
from ..static_analysis.hasher import CANONICALIZATION_VERSION

BASELINE_SCHEMA = "audit-baseline"
BASELINE_VERSION = "2.0"


def build_baseline(doc: AuditDocument) -> Dict[str, Any]:
    identities = sorted({s.handshake.identity or "" for s in doc.servers})
    return {
        "schema": BASELINE_SCHEMA, "version": BASELINE_VERSION, "created_at": time.time(),
        "target": {"id": doc.target.get("id"), "build_ref": doc.target.get("build_ref"), "environment": doc.target.get("environment")},
        "context": {"mode": doc.mode.value, "identities": identities, "schema_version": AUDIT_SCHEMA_VERSION,
                    "ruleset_version": RULESET_VERSION, "canonicalization_version": CANONICALIZATION_VERSION,
                    "inventory_sources": {s.name: s.handshake.source for s in doc.servers}},
        "hash_baseline": dict(sorted(doc.hash_baseline.items())),
        "servers": sorted(s.name for s in doc.servers),
        "tools": sorted(t.qualified_name for t in doc.all_tools()),
        "instructions": {s.name: (s.handshake.instructions or "") for s in doc.servers},
        "server_identity": {s.name: {"server_info": s.handshake.server_info, "url": s.url, "command": s.command,
                                     "protocol_version": s.handshake.protocol_version} for s in doc.servers},
        "policy_digest": _digest({k: v for k, v in doc.policy.items() if not k.startswith("_")}) if doc.policy else None,
        "policy_version": doc.policy.get("version") if doc.policy else None,
        "service_rights_digest": _digest(doc.policy.get("service_rights") or {}) if doc.policy else None,
        "memory_schema_digest": _digest(doc.profile.get("memory_stores") or []) if doc.profile else None,
        "retrieval_config_digest": _digest([f for f in (doc.source_facts.get("flows") or []) if f.get("kind") in ("memory_read", "context_include")]),
        "egress_config_digest": _digest([f for f in (doc.source_facts.get("flows") or []) if f.get("kind") == "transmit"] + [doc.policy.get("egress") or {}]),
        "access_digest": _digest({s.name: s.effective_access.get("policy_expected") for s in doc.servers}),
        "runtime_config_digest": _digest({"reproducibility": doc.meta.get("reproducibility"), "deployment": {k: v.get("env_keys") for k, v in (doc.deployment.get("services") or {}).items()}}),
        "coverage": {c.metric: c.ratio for c in doc.coverage},
        "inventory_completeness": {s.name: s.inventory_sources.get("summary") for s in doc.servers},
        "approval_state": ApprovalState.UNKNOWN.value,
        "approval_note": "a new snapshot is not approved by being produced by the auditor",
    }


def save_baseline(doc: AuditDocument, path: str) -> Dict[str, Any]:
    baseline = build_baseline(doc)
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(baseline, fh, indent=2, ensure_ascii=False)
    return baseline


def load_baseline(path: str) -> Dict[str, Any]:
    with open(path, "r", encoding="utf-8") as fh:
        return json.load(fh)


def load_approvals(path: Optional[str]) -> Dict[str, Any]:
    """``{"approvals": {"server/tool": {"state": "approved", "hash": "...", "by": "...", "at": ...}}}``."""
    if not path:
        return {}
    with open(path, "r", encoding="utf-8") as fh:
        data = json.load(fh)
    return data.get("approvals") or data


def _compatibility(old: Dict[str, Any], cur: Dict[str, Any]) -> Dict[str, Any]:
    reasons: List[str] = []
    old_v = old.get("version") or "1.x"
    if old.get("schema") not in (BASELINE_SCHEMA, "audit-baseline"):
        reasons.append("old file is not an audit baseline")
    if str(old_v).split(".")[0] != BASELINE_VERSION.split(".")[0]:
        reasons.append(f"baseline schema {old_v} vs {BASELINE_VERSION}: legacy baseline; comparison limited to definition hashes and names")
    oc, cc = old.get("context") or {}, cur.get("context") or {}
    ot, ct = old.get("target") or {}, cur.get("target") or {}
    if ot.get("id") and ct.get("id") and ot["id"] != ct["id"]:
        reasons.append(f"different targets: {ot['id']} vs {ct['id']}")
    if ot.get("environment") and ct.get("environment") and ot["environment"] != ct["environment"]:
        reasons.append(f"different environments: {ot['environment']} vs {ct['environment']}")
    if oc.get("identities") and cc.get("identities") and oc["identities"] != cc["identities"]:
        reasons.append(f"different discovery identities/roles: {oc['identities']} vs {cc['identities']}")
    hash_comparable = (oc.get("canonicalization_version") or "1") == cc.get("canonicalization_version")
    if not hash_comparable:
        reasons.append(f"canonicalization {oc.get('canonicalization_version') or '1'} vs {cc.get('canonicalization_version')}: "
                       "hash differences are not target changes")
    rules_changed = bool(oc.get("ruleset_version")) and oc.get("ruleset_version") != cc.get("ruleset_version")
    fatal = any(r.startswith("different targets") or r.startswith("old file is not") for r in reasons)
    return {"comparable": not fatal, "hash_comparable": hash_comparable, "limited": bool(reasons), "reasons": reasons,
            "ruleset_changed": rules_changed,
            "ruleset_versions": {"baseline": oc.get("ruleset_version"), "current": cc.get("ruleset_version")}}


def diff_baseline(old: Dict[str, Any], doc: AuditDocument, approvals: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    cur = build_baseline(doc)
    compat = _compatibility(old, cur)
    approvals = approvals or {}
    changes: List[Dict[str, Any]] = []

    def approval_for(key: str, new_hash: Optional[str]) -> str:
        a = approvals.get(key)
        if not a:
            return ApprovalState.UNKNOWN.value
        if a.get("hash") and new_hash and a["hash"] != new_hash:
            return ApprovalState.PENDING.value
        return a.get("state", ApprovalState.UNKNOWN.value)

    if not compat["comparable"]:
        return {"compatibility": compat, "changes": [{"kind": ChangeKind.COMPARISON_INCONCLUSIVE.value, "detail": "; ".join(compat["reasons"])}],
                "clean": None, "approval_state": ApprovalState.UNKNOWN.value, "summary": "comparison inconclusive",
                "interpretation": "snapshots are not comparable; no drift conclusion"}
    old_h: Dict[str, str] = old.get("hash_baseline", {})
    cur_h: Dict[str, str] = cur["hash_baseline"]
    for key in sorted(set(cur_h) & set(old_h)):
        if old_h[key] != cur_h[key]:
            if compat["hash_comparable"]:
                changes.append({"kind": ChangeKind.DEFINITION_CHANGED.value, "key": key, "old": old_h[key], "new": cur_h[key],
                                "approval_state": approval_for(key, cur_h[key]),
                                "interpretation": "definition drift; approval state decides whether it is accepted; malicious intent is not established by the change"})
            else:
                changes.append({"kind": ChangeKind.COMPARISON_INCONCLUSIVE.value, "key": key,
                                "detail": "hash differs but canonicalization versions differ; re-baseline required"})
    for key in sorted(set(cur_h) - set(old_h)):
        changes.append({"kind": ChangeKind.ADDED.value, "key": key, "new": cur_h[key], "approval_state": approval_for(key, cur_h[key])})
    for key in sorted(set(old_h) - set(cur_h)):
        changes.append({"kind": ChangeKind.REMOVED.value, "key": key, "old": old_h[key], "approval_state": approval_for(key, None),
                        "interpretation": "removed from this catalogue; with partial discovery this is not proof of removal from the server"})
    for srv in sorted(set(cur["servers"]) - set(old.get("servers", []))):
        changes.append({"kind": ChangeKind.ADDED.value, "key": f"server:{srv}", "approval_state": approval_for(f"server:{srv}", None),
                        "interpretation": "new server: full audit required"})
    for srv in sorted(set(old.get("servers", [])) - set(cur["servers"])):
        changes.append({"kind": ChangeKind.REMOVED.value, "key": f"server:{srv}", "approval_state": approval_for(f"server:{srv}", None)})
    for field_, kind in (("policy_digest", ChangeKind.POLICY_CHANGED), ("service_rights_digest", ChangeKind.ACCESS_CHANGED),
                         ("access_digest", ChangeKind.ACCESS_CHANGED), ("memory_schema_digest", ChangeKind.POLICY_CHANGED),
                         ("retrieval_config_digest", ChangeKind.RUNTIME_CONFIG_CHANGED),
                         ("egress_config_digest", ChangeKind.RUNTIME_CONFIG_CHANGED),
                         ("runtime_config_digest", ChangeKind.RUNTIME_CONFIG_CHANGED)):
        if field_ in old and old.get(field_) != cur.get(field_):
            changes.append({"kind": kind.value, "key": field_, "old": old.get(field_), "new": cur.get(field_),
                            "approval_state": approval_for(field_, cur.get(field_)),
                            "interpretation": f"{field_} changed between compatible snapshots; review and record approval"})
    oc, cc = old.get("coverage") or {}, cur.get("coverage") or {}
    for metric in sorted(set(oc) | set(cc)):
        if oc.get(metric) != cc.get(metric):
            changes.append({"kind": ChangeKind.COVERAGE_CHANGED.value, "key": metric, "old": oc.get(metric), "new": cc.get(metric)})
    if compat["ruleset_changed"]:
        changes.append({"kind": ChangeKind.RUNTIME_CONFIG_CHANGED.value, "key": "ruleset_version",
                        "old": compat["ruleset_versions"]["baseline"], "new": compat["ruleset_versions"]["current"],
                        "interpretation": "rule version changed: findings may differ without a change of the target"})
    states = {c.get("approval_state") for c in changes if "approval_state" in c}
    if not states:
        overall = ApprovalState.UNKNOWN.value if changes else ApprovalState.APPROVED.value
    elif states == {ApprovalState.APPROVED.value}:
        overall = ApprovalState.APPROVED.value
    elif ApprovalState.REJECTED.value in states:
        overall = ApprovalState.REJECTED.value
    elif ApprovalState.PENDING.value in states or ApprovalState.UNKNOWN.value in states:
        overall = ApprovalState.PENDING.value if ApprovalState.PENDING.value in states else ApprovalState.UNKNOWN.value
    else:
        overall = ApprovalState.UNKNOWN.value
    material = [c for c in changes if c["kind"] not in (ChangeKind.COVERAGE_CHANGED.value,)]
    return {
        "compatibility": compat, "changes": changes,
        "counts": {k.value: sum(1 for c in changes if c["kind"] == k.value) for k in ChangeKind},
        "clean": not material, "approval_state": overall,
        "summary": ("no material change" if not material else f"{len(material)} material change(s); approval {overall}"),
        "interpretation": "drift describes what differs between compatible snapshots; it is not a proof of a rug pull",
        "baseline_target": old.get("target"), "current_target": cur["target"],
    }


def run_drift(doc: AuditDocument, baseline_path: str, store=None, approvals_path: Optional[str] = None) -> Dict[str, Any]:
    from ..evidence import EvidenceStore
    store = store or EvidenceStore(doc)
    old = load_baseline(baseline_path)
    approvals = load_approvals(approvals_path)
    result = diff_baseline(old, doc, approvals)
    ev = store.add(SourceType.BASELINE, Method.PARSING, {"path": baseline_path, "baseline_version": old.get("version")},
                   digest=_digest(old.get("hash_baseline") or {}), summary=f"baseline {old.get('version')} from {baseline_path}",
                   limitations=list(result.get("compatibility", {}).get("reasons") or []))
    result["evidence_ref"] = ev.evidence_id
    doc.drift = result
    return result
