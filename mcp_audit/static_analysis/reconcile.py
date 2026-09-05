"""Inventory reconciliation (TZ §6): configured / source_defined / live_advertised /
runtime_observed / policy_authorized compared per server after matching the
server identity, build, role and snapshot time.

Sources may diverge legitimately; the reconciliation records the difference
with its context and leaves the interpretation to INV-01 / TOOL-02.
"""
from __future__ import annotations

from typing import Any, Dict, List, Optional

from ..models import AuditDocument, ServerRecord
from .schema_analyzer import compare_contracts


def _configured(server: ServerRecord) -> Optional[Dict[str, Dict[str, Any]]]:
    cfg = server.inventory_sources.get("configured") or {}
    defs = cfg.get("definitions")
    if defs is None:
        if cfg.get("count") and server.handshake.source == "config":
            return {t.name: t.definition.raw for t in server.tools}
        return None
    return {d.get("name"): d for d in defs}


def _live(server: ServerRecord) -> Optional[Dict[str, Dict[str, Any]]]:
    if server.handshake.source in ("live", "snapshot") and (server.handshake.ok or server.handshake.source == "snapshot"):
        return {t.name: t.definition.raw for t in server.tools}
    return None


def _source_defined(doc: AuditDocument, server: ServerRecord) -> Optional[Dict[str, Dict[str, Any]]]:
    decls = [d for d in (doc.source_facts.get("tool_declarations") or [])
             if d.get("status") != "unknown" and d.get("component") in (server.name, server.component_id)]
    if not decls and not any(d.get("component") in (server.name, server.component_id) for d in doc.source_facts.get("tool_declarations") or []):
        return None
    return {d["name"]: {"name": d["name"], "description": d.get("description"), "inputSchema": d.get("input_schema"),
                        "evidence_refs": d.get("evidence_refs") or [], "path": d.get("path")} for d in decls}


def _policy_authorized(doc: AuditDocument, server: ServerRecord) -> Optional[Dict[str, Dict[str, Any]]]:
    auth = doc.policy.get("authorized_tools") or {}
    names = auth.get(server.name) or auth.get(server.component_id)
    if names is None:
        return None
    return {n: {"name": n} for n in names}


def _runtime_observed(doc: AuditDocument, server: ServerRecord) -> Optional[Dict[str, Dict[str, Any]]]:
    if not doc.trace_events:
        return None
    seen: Dict[str, Dict[str, Any]] = {}
    for ev in doc.trace_events:
        tool = ev.get("tool") or {}
        qid = tool.get("qualified_id") or ""
        if qid.startswith(server.name + "/"):
            seen[qid.split("/", 1)[1]] = {"name": qid.split("/", 1)[1], "event_id": ev.get("event_id")}
    return seen


def reconcile_inventory(doc: AuditDocument) -> List[Dict[str, Any]]:
    out: List[Dict[str, Any]] = []
    for s in doc.servers:
        sources: Dict[str, Optional[Dict[str, Dict[str, Any]]]] = {
            "configured": _configured(s), "source_defined": _source_defined(doc, s), "live_advertised": _live(s),
            "runtime_observed": _runtime_observed(doc, s), "policy_authorized": _policy_authorized(doc, s),
        }
        present = {k: v for k, v in sources.items() if v is not None}
        s.inventory_sources["summary"] = {k: (len(v) if v is not None else None) for k, v in sources.items()}
        keys = list(present)
        context = {"server": s.name, "component_id": s.component_id, "build_ref": doc.target.get("build_ref"),
                   "identity": s.handshake.identity, "captured_at": s.handshake.captured_at}
        for i, a in enumerate(keys):
            for b in keys[i + 1:]:
                if b == "runtime_observed":
                    continue       # runtime usage is a subset by nature; not a mismatch
                na, nb = set(present[a]), set(present[b])
                only_a, only_b = sorted(na - nb), sorted(nb - na)
                refs = []
                for name in only_b:
                    refs += (present[b][name].get("evidence_refs") or [])
                for name in only_a:
                    refs += (present[a][name].get("evidence_refs") or [])
                if only_a or only_b:
                    out.append({"kind": "inventory_mismatch", "server": s.name, "pair": f"{a}/{b}", "sources": [a, b],
                                "only_in_a": only_a, "only_in_b": only_b, "common": len(na & nb), "context": context,
                                "detail": f"{s.name}: {len(na)} {a} vs {len(nb)} {b}; {len(na & nb)} common; "
                                          f"only in {a}: {only_a or '-'}; only in {b}: {only_b or '-'}",
                                "ratio_note": f"{len(na & nb)}/{max(len(na), len(nb))} is the share of matching names between these two "
                                              "catalogues only - not a percentage of verified security and not a measurement of the running deployment",
                                "evidence_refs": refs})
                else:
                    out.append({"kind": "inventory_match", "server": s.name, "pair": f"{a}/{b}", "sources": [a, b],
                                "common": len(na), "context": context})
                # contract comparison for common tools
                for name in sorted(na & nb):
                    sa, sb = present[a][name].get("inputSchema") or {}, present[b][name].get("inputSchema") or {}
                    if not (isinstance(sa, dict) and sa.get("properties") is not None) or \
                            not (isinstance(sb, dict) and sb.get("properties") is not None):
                        continue          # a name-only catalogue (policy list, runtime usage) has no contract to compare
                    diffs = compare_contracts(sa, sb, label_a=a, label_b=b)
                    breaking = [d for d in diffs if d.get("breaking")]
                    entry = {"kind": "contract_mismatch" if breaking else ("contract_incomplete" if diffs else "contract_match"), "server": s.name,
                             "tool": f"{s.name}/{name}", "tool_name": name, "pair": f"{a}/{b}", "sources": [a, b],
                             "differences": diffs, "context": context,
                             "evidence_refs": (present[b][name].get("evidence_refs") or []) + (present[a][name].get("evidence_refs") or [])}
                    if diffs:
                        entry["detail"] = f"{s.name}/{name}: {a} vs {b} - " + "; ".join(f"{d['parameter']}: {d['detail']}" for d in diffs)
                        if not breaking:
                            entry["detail"] += " (optional parameters only; calls with the smaller schema still fit the larger one)"
                    out.append(entry)
                    for t in s.tools:
                        if t.name == name:
                            t.contract.setdefault("comparisons", []).append({"pair": f"{a}/{b}", "differences": diffs})
        if len(present) < 2:
            out.append({"kind": "single_source", "server": s.name, "sources": keys, "context": context,
                        "detail": f"{s.name}: only {keys or 'no'} inventory source(s); nothing to reconcile"})
    doc.inventory_reconciliation = out
    return out
