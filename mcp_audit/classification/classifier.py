"""Operation classifier (TZ §7).

Replaces the single READ/WRITE/EXEC/DELETE label with independent properties:

  * ``classification``        - primary class (kept for continuity);
  * ``operations``            - direct operations (READ, CREATE, UPDATE, DELETE, EXECUTE, PUBLISH, TRANSMIT);
  * ``side_effects``          - effects of *other* components linked by a causal reference
                                 (e.g. the orchestrator storing the final answer); they never
                                 change the tool's own class;
  * ``executing_principal``, ``phase``, ``target_scope``;
  * ``classification_basis``  - definition | source_inference | policy_snapshot | runtime_observation;
  * ``knowledge_state``       - known | assumed | unknown | contradictory.

Name/description heuristics are *assumptions* (basis ``definition``); MCP
annotations are self-report and only used as hints.
"""
from __future__ import annotations

import re
from typing import Any, Dict, List, Optional

from ..models import AuditDocument, KnowledgeState, Operation, PRIMARY_TO_OPS, ToolRecord

_EXEC = re.compile(r"\b(exec|execute|command|shell|spawn|eval|bash|subprocess|terminal|run_command|"
                   r"выполн\w+|исполн\w+)\b", re.I)
_EXEC_DESC = re.compile(r"\b(execute|run)\b[^.\n]{0,30}\b(command|shell|script|code|binary|process|program)\b|"
                        r"\b(shell\s+command|arbitrary\s+(code|command))\b|"
                        r"(выполн\w+|запуст\w+|исполн\w+)[^.\n]{0,30}(команд\w+|скрипт\w+|код\b|shell)", re.I)
_DELETE = re.compile(r"\b(delete|remove|rm|unlink|drop|truncate|purge|destroy|erase|rmdir|wipe)\b|"
                     r"(удал\w+|стере\w+|очист\w+|сброс\w+|уничтож\w+)", re.I)
_CREATE = re.compile(r"\b(create|insert|add|mkdir|upload|post|publish|new)\b|(созда\w+|добав\w+|загруз\w+|опублик\w+)", re.I)
_WRITE = re.compile(r"\b(write|create|update|edit|modify|append|put|post|insert|set|save|upload|patch|move|rename|mkdir|chmod|push|commit|merge|send|publish|comment)\b|"
                    r"(созда\w+|запис\w+|измен\w+|обнов\w+|добав\w+|сохран\w+|отправ\w+|установ\w+|переимен\w+|перемест\w+|редактир\w+)", re.I)
_READ = re.compile(r"\b(read|get|list|search|find|fetch|query|show|describe|cat|view|stat|info|head|tail|grep|resolve|check|scan|analyze|inspect)\b|"
                   r"(получ\w+|прочит\w+|чтен\w+|список|списки|показ\w+|найти|найд\w+|поиск\w*|искать|запрос\w+|провер\w+|узна\w+|верн\w+|отобрази\w+|вывес\w+)", re.I)
_PUBLISH = re.compile(r"\b(publish|broadcast|announce)\b|(опублик\w+|разослат\w+)", re.I)
_TRANSMIT = re.compile(r"\b(send|post|upload|email|mail|transmit|forward|webhook|notify|slack)\b|(отправ\w+|переда\w+|уведом\w+)", re.I)

_SENSITIVE = re.compile(
    r"\b(secret|credential|token|key|password|env|environment|config|\.ssh|private|billing|payment|customer|user|personal|pii|email|message|dm|inbox|"
    r"portfolio|holdings|positions?|balance|tax|broker|account|dividend|transaction|order|trade|financial)\b|"
    r"(портфел\w+|позици\w+|остат\w+|баланс\w+|налог\w+|брокер\w+|счёт\w*|счет\w*|клиент\w+|"
    r"дивиденд\w+|операц\w+|истори\w+\s+операц\w+|сдел\w+|владел\w+|персональн\w+)",
    re.I)
_UNTRUSTED = re.compile(r"\b(read|fetch|get|list|search|query|web|http|url|browse|issue|pull|comment|review|message|email|inbox|log|stdout|output|page|content|document|file)\b", re.I)
_EGRESS = re.compile(r"\b(http|https|url|fetch|request|post|upload|send|email|mail|slack|webhook|publish|create_pull|create_issue|comment|push|forward|transmit|net|network|browse|dns|web|internet)\b|"
                     r"(поиск\s+в\s+интернет\w*|веб-поиск|интернет)", re.I)

_NETWORK_KINDS = ("fetch", "github", "gitlab", "slack", "email")


def _split(s: str) -> str:
    s = re.sub(r"([a-z0-9])([A-Z])", r"\1 \2", s)
    return re.sub(r"[_\W]+", " ", s, flags=re.UNICODE)


def _text(t: ToolRecord) -> str:
    return _split(f"{t.name} {t.definition.title or ''} {t.definition.description}")


def classify_tool(tool: ToolRecord, server_kind: str = "generic", network_access: bool = False) -> ToolRecord:
    text = _text(tool)
    ann = tool.definition.annotations or {}
    name = _split(tool.name)
    desc = tool.definition.description[:300]

    op = Operation.UNKNOWN
    basis_note = "name"
    if _EXEC.search(name) or (server_kind == "shell") or _EXEC_DESC.search(desc):
        op = Operation.EXEC
    elif _DELETE.search(name):
        op = Operation.DELETE
    elif _WRITE.search(name):
        op = Operation.WRITE
    elif _READ.search(name):
        op = Operation.READ
    else:
        basis_note = "description"
        if _DELETE.search(text):
            op = Operation.DELETE
        elif _WRITE.search(text):
            op = Operation.WRITE
        elif _READ.search(text):
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
        ops = ["CREATE"] if _CREATE.search(name) and not re.search(r"\b(update|edit|modify|patch|set)\b", name, re.I) else ["CREATE", "UPDATE"]
    if _PUBLISH.search(name) and "PUBLISH" not in ops:
        ops.append("PUBLISH")
    egress_hint = bool(_EGRESS.search(text)) or server_kind in _NETWORK_KINDS or (network_access and op != Operation.READ)
    if (_TRANSMIT.search(name) or server_kind in ("fetch", "native", "email", "slack") or egress_hint) and op != Operation.EXEC:
        if "TRANSMIT" not in ops and (egress_hint or _TRANSMIT.search(name)):
            ops.append("TRANSMIT")
    if op == Operation.EXEC:
        ops = ["EXECUTE", "READ", "CREATE", "UPDATE", "DELETE", "TRANSMIT"]   # execution implies everything reachable
    tool.operations = ops
    tool.classification_basis = "definition"
    tool.knowledge_state = KnowledgeState.ASSUMED if op != Operation.UNKNOWN else KnowledgeState.UNKNOWN
    tool.destructive = (op == Operation.DELETE) or bool(_DELETE.search(name)) or \
        (ann.get("destructiveHint") is True) or bool(re.search(r"truncate|drop|purge|force", text, re.I))
    tool.declared_hints = {k: v for k, v in ann.items() if k.endswith("Hint")}
    tool.provenance["classification"] = f"definition:{basis_note}"

    reads = op in (Operation.READ, Operation.EXEC)
    tool.sensitive_source = bool(reads and (_SENSITIVE.search(text) or server_kind in ("filesystem", "postgres", "sqlite", "memory", "email", "slack")))
    tool.untrusted_input = bool((op in (Operation.READ, Operation.EXEC)) and _UNTRUSTED.search(text)) or server_kind in ("fetch", "github", "gitlab", "slack", "email")
    tool.egress = egress_hint or (op == Operation.EXEC) or "TRANSMIT" in ops
    if op == Operation.EXEC:
        tool.sensitive_source = True
        tool.egress = True
    if tool.egress and "TRANSMIT" not in tool.operations:
        tool.operations.append("TRANSMIT")
    tool.phase = "request_handling"
    tool.executing_principal = None          # unknown until policy / source says who executes the call
    return tool


def classify_all(doc: AuditDocument) -> None:
    for s in doc.servers:
        net = bool(s.overrides.get("network_access")) or s.kind in _NETWORK_KINDS
        for t in s.tools:
            classify_tool(t, server_kind=s.kind, network_access=net)
            if s.overrides.get("executing_principal"):
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
    a name still does not define its side effects."""
    decls = {(d.get("component"), d.get("name")): d for d in (doc.source_facts.get("tool_declarations") or [])
             if d.get("status") != "unknown"}
    for s in doc.servers:
        for t in s.tools:
            d = decls.get((s.name, t.name)) or decls.get((s.component_id, t.name))
            if d:
                t.classification_basis = "source_inference"
                t.claim_refs = list(dict.fromkeys(t.claim_refs + [f"CL-DECL-{s.name}-{t.name}"]))
                t.provenance["declaration"] = "source_defined"
