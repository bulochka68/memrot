"""Operation classifier (TZ §7).

Replaces the single READ/WRITE/EXEC/DELETE label with independent properties:

  * ``classification``        - primary class (kept for continuity);
  * ``operations``            - direct operations (READ, CREATE, UPDATE, DELETE, EXECUTE, PUBLISH, TRANSMIT);
  * ``side_effects``          - effects of *other* components linked by a causal reference
                                 (e.g. the orchestrator storing the final answer); they never
                                 change the tool's own class;
  * ``executing_principal``, ``phase``, ``target_scope``;
  * ``classification_basis``  - declared | definition | source_inference | policy_snapshot | runtime_observation;
  * ``knowledge_state``       - known | assumed | unknown | contradictory.

Resolution order of every property: **declared > annotation > heuristic > unknown**
(:mod:`mcp_audit.classification.declared`).  Name/description heuristics are
*assumptions* (basis ``definition``); MCP annotations are self-report and only
used as hints; a declaration is the config/profile author speaking, so it is
recorded as ``declared`` and still stays ``assumed`` knowledge.

The vocabulary the heuristics use is data (:mod:`mcp_audit.classification.lexicon`,
``mcp_audit/data/lexicon.json``): a new stand teaches the engine its own domain
verbs through ``profile.lexicon`` instead of patching this module.
"""
from __future__ import annotations

import re
from typing import Any, Dict, List, Optional

from ..models import AuditDocument, KnowledgeState, Operation, PRIMARY_TO_OPS, ServerRecord, ToolRecord
from .declared import apply_declaration, declaration_for
from .lexicon import Lexicon, base_lexicon, load_lexicon


def _split(s: str) -> str:
    s = re.sub(r"([a-z0-9])([A-Z])", r"\1 \2", s)
    return re.sub(r"[_\W]+", " ", s, flags=re.UNICODE)


def _text(t: ToolRecord) -> str:
    return _split(f"{t.name} {t.definition.title or ''} {t.definition.description}")


def classify_tool(tool: ToolRecord, server_kind: str = "generic", network_access: bool = False,
                  lexicon: Optional[Lexicon] = None, declared: Optional[Dict[str, Any]] = None,
                  declaration_origin: str = "declared", declaration_problems: Optional[List[str]] = None) -> ToolRecord:
    lex = lexicon or base_lexicon()
    text = _text(tool)
    ann = tool.definition.annotations or {}
    name = _split(tool.name)
    desc = tool.definition.description[:300]

    op = Operation.UNKNOWN
    basis_note = "name"
    if lex.search("operations", "exec", name) or (server_kind in lex.kind_role("exec")) \
            or lex.search("signals", "exec_description", desc):
        op = Operation.EXEC
    elif lex.search("operations", "delete", name):
        op = Operation.DELETE
    elif lex.search("operations", "write", name):
        op = Operation.WRITE
    elif lex.search("operations", "read", name):
        op = Operation.READ
    else:
        basis_note = "description"
        if lex.search("operations", "delete", text):
            op = Operation.DELETE
        elif lex.search("operations", "write", text):
            op = Operation.WRITE
        elif lex.search("operations", "read", text):
            op = Operation.READ
        elif ann.get("readOnlyHint") is True:
            op = Operation.READ
            basis_note = "annotation(self-report)"
        else:
            op = Operation.UNKNOWN
            basis_note = "none"

    tool.classification = op
    ops: List[str] = list(PRIMARY_TO_OPS[op])
    if op == Operation.WRITE:
        ops = ["CREATE"] if lex.search("operations", "create", name) and not lex.search("operations", "update", name) \
            else ["CREATE", "UPDATE"]
    if lex.search("signals", "publish", name) and "PUBLISH" not in ops:
        ops.append("PUBLISH")
    egress_hint = lex.search("signals", "egress", text) or server_kind in lex.network_kinds or \
        (network_access and op != Operation.READ)
    transmit_name = lex.search("signals", "transmit", name)
    if (transmit_name or server_kind in lex.kind_role("transmit") or egress_hint) and op != Operation.EXEC:
        if "TRANSMIT" not in ops and (egress_hint or transmit_name):
            ops.append("TRANSMIT")
    if op == Operation.EXEC:
        ops = ["EXECUTE", "READ", "CREATE", "UPDATE", "DELETE", "TRANSMIT"]   # execution implies everything reachable
    tool.operations = ops
    tool.classification_basis = "definition"
    tool.knowledge_state = KnowledgeState.ASSUMED if op != Operation.UNKNOWN else KnowledgeState.UNKNOWN
    tool.destructive = (op == Operation.DELETE) or bool(lex.search("operations", "delete", name)) or \
        (ann.get("destructiveHint") is True) or bool(lex.search("signals", "destructive", text))
    tool.declared_hints = {k: v for k, v in ann.items() if k.endswith("Hint")}
    tool.provenance["classification"] = f"definition:{basis_note}"

    reads = op in (Operation.READ, Operation.EXEC)
    tool.sensitive_source = bool(reads and (lex.search("signals", "sensitive", text)
                                            or server_kind in lex.kind_role("sensitive_source")))
    tool.untrusted_input = bool((op in (Operation.READ, Operation.EXEC)) and lex.search("signals", "untrusted", text)) \
        or server_kind in lex.kind_role("untrusted_input")
    tool.egress = egress_hint or (op == Operation.EXEC) or "TRANSMIT" in ops
    if op == Operation.EXEC:
        tool.sensitive_source = True
        tool.egress = True
    if tool.egress and "TRANSMIT" not in tool.operations:
        tool.operations.append("TRANSMIT")
    tool.phase = "request_handling"
    tool.executing_principal = None          # unknown until policy / source says who executes the call

    if declared or declaration_problems:
        apply_declaration(tool, declared or {}, declaration_origin, declaration_problems)
    return tool


def classify_all(doc: AuditDocument) -> None:
    lex = load_lexicon(doc.profile)
    repro = doc.meta.setdefault("reproducibility", {})
    if isinstance(repro, dict):
        repro["lexicon"] = lex.summary()
    # declarations written next to the definitions in the stand's own source registry
    source_declared = {(d.get("component"), d.get("name")): d["declared"]
                       for d in (doc.source_facts.get("tool_declarations") or [])
                       if d.get("status") != "unknown" and isinstance(d.get("declared"), dict) and d["declared"]}
    for s in doc.servers:
        net = bool(s.overrides.get("network_access")) or s.kind in lex.network_kinds
        refs = doc.server_refs(s)
        for t in s.tools:
            from_source = next((source_declared[(ref, t.name)] for ref in refs if (ref, t.name) in source_declared), None)
            declared, origin, problems = declaration_for(s, t, doc.profile, from_source)
            classify_tool(t, server_kind=s.kind, network_access=net, lexicon=lex, declared=declared,
                          declaration_origin=origin or "declared", declaration_problems=problems)
            if s.overrides.get("executing_principal") and not declared.get("executing_principal"):
                t.executing_principal = s.overrides["executing_principal"]
                t.provenance["executing_principal"] = "x_audit(expected)"
    attach_side_effects(doc)
    attach_source_basis(doc)


def attach_side_effects(doc: AuditDocument) -> None:
    """Side effects of *other* components (profile ``side_effects``) are linked by a causal
    reference and never change the tool's own class (TZ §7)."""
    for se in doc.profile.get("side_effects") or []:
        applies = se.get("applies_to") or {}
        for s in doc.servers:
            if applies.get("servers") and s.name not in applies["servers"]:
                continue
            for t in s.tools:
                if applies.get("tools") and t.name not in applies["tools"]:
                    continue
                t.side_effects.append({
                    "effect": se.get("effect"), "component": se.get("component"), "phase": se.get("phase", "finalization"),
                    "memory_type": se.get("memory_type"), "causal_ref": se.get("flow_ref"),
                    "basis": se.get("basis", "source_inference"), "note": "effect of another component; does not reclassify the tool",
                })


def attach_source_basis(doc: AuditDocument) -> None:
    """When the source adapter found the declaration, the classification basis is upgraded to
    ``source_inference`` with the declaration's evidence, and the knowledge state stays assumed:
    a name still does not define its side effects.  An explicit ``declared`` basis is kept:
    what the author stated outranks what the engine inferred from the code's shape."""
    decls = {(d.get("component"), d.get("name")): d for d in (doc.source_facts.get("tool_declarations") or [])
             if d.get("status") != "unknown"}
    for s in doc.servers:
        refs = doc.server_refs(s)
        for t in s.tools:
            d = next((decls[(ref, t.name)] for ref in refs if (ref, t.name) in decls), None)
            if d:
                if t.classification_basis != "declared":
                    t.classification_basis = "source_inference"
                t.claim_refs = list(dict.fromkeys(t.claim_refs + [f"CL-DECL-{s.name}-{t.name}"]))
                t.provenance["declaration"] = "source_defined"
