"""Policy snapshot adapter: the *expected* access and memory policy.

A policy snapshot states who may read / write / publish what, which server
checks are mandatory, how tokens must be validated and what may leave the
system.  A valid token does not give a right to any object; the policy is a
declaration of expectations, not proof of enforcement (TZ §5.1, §5.3).
"""
from __future__ import annotations

import hashlib
import os
from typing import Any, Dict, List

from ..models import AuditDocument, Method, SourceType
from ..evidence import EvidenceStore
from ..identity import build_principals
from .base import Adapter, AdapterResult
from .registry import register

POLICY_SCHEMA = "access-policy"
KNOWN_SECTIONS = ("principals", "access_rules", "boundaries", "memory_policy", "authentication",
                  "mandatory_server_checks", "service_rights", "network", "egress", "tool_approval",
                  "authorized_tools", "retention", "revocation")


@register
class PolicySnapshotAdapter(Adapter):
    kind = "policy_snapshot"
    adapter_version = "2.0.0"
    supported = list(KNOWN_SECTIONS)
    unsupported = {
        "enforcement_proof": "a policy declares expectations; enforcement is established by source, deployment or observation",
        "live_iam_query": "IAM systems are not queried; provide a snapshot",
    }

    def collect(self, doc: AuditDocument, store: EvidenceStore) -> AdapterResult:
        path = self.binding.path("path")
        if not path or not os.path.isfile(path):
            return AdapterResult(self.status("unavailable", [f"policy snapshot not found: {path}"]))
        data = self._read_json(path)
        if not isinstance(data, dict) or (data.get("schema") not in (None, POLICY_SCHEMA)):
            return AdapterResult(self.status("unavailable", [f"{path}: not an {POLICY_SCHEMA} document"]))
        with open(path, "rb") as fh:
            dg = "sha256:" + hashlib.sha256(fh.read()).hexdigest()
        ev = store.add(SourceType.POLICY_SNAPSHOT, Method.POLICY_INSPECTION,
                       {"path": os.path.relpath(path), "policy_id": data.get("policy_id"), "version": data.get("version")},
                       digest=dg, adapter=self.kind, adapter_version=self.adapter_version,
                       summary=f"access/memory policy {data.get('policy_id')} v{data.get('version')} owned by {data.get('owner')}",
                       limitations=["declared expectations; not evidence of enforcement"])
        extensions = {k: v for k, v in data.items() if k not in KNOWN_SECTIONS + ("schema", "version", "policy_id", "owner")}
        policy = {k: v for k, v in data.items() if k not in extensions}
        policy["_evidence_ref"] = ev.evidence_id
        if extensions:
            policy["extensions"] = {"x-policy": extensions}
        doc.policy = policy
        for p in build_principals(policy, doc.profile):
            if not any(x.principal_id == p.principal_id for x in doc.principals):
                p.evidence_refs.append(ev.evidence_id)
                doc.principals.append(p)
        missing = [s for s in ("memory_policy", "access_rules", "authentication") if s not in policy]
        reasons: List[str] = [f"policy has no '{s}' section; dependent controls stay not_evaluated" for s in missing]
        return AdapterResult(self.status("partial" if missing else "available", reasons, evidence_count=1),
                             facts={"policy_evidence": ev.evidence_id})
