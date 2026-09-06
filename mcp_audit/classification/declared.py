"""Explicit capability declarations (portability P0-2).

A property of a tool can be *declared* instead of guessed.  Two places carry a
declaration, both of them data:

* the MCP config, next to the tool definition::

      {"name": "add_drawer", "description": "…", "inputSchema": {…},
       "x_audit": {"operations": ["CREATE"], "egress": false, "sensitive_source": true}}

* the stand's own source registry, when the definitions live in the code
  (``x_audit`` inside a ``registry_dict`` / ``json_file`` entry);

* the profile, when the stand's own config must not be touched::

      "capabilities": {"mempalace/add_drawer": {"operations": ["CREATE"], "egress": false},
                       "mempalace/*":          {"untrusted_input": true},
                       "status":               {"operations": ["READ"]}}

Resolution order for every property: **declared > annotation > heuristic > unknown**.

A declaration is an input, not a conclusion:

* ``classification_basis`` becomes ``declared`` and ``provenance.classification``
  records who declared it, so a report never confuses "we were told" with
  "we observed";
* ``knowledge_state`` stays ``assumed`` - the author of a config is not evidence;
  ``known`` still requires a handshake or the code;
* a declaration that contradicts the server's own annotation is recorded as a
  discrepancy (``contract.declaration_vs_annotation``, knowledge state
  ``contradictory``) instead of silently winning.
"""
from __future__ import annotations

from typing import Any, Dict, List, Optional, Tuple

from ..models import KnowledgeState, Operation, ServerRecord, ToolRecord

#: properties that may be declared
DECLARABLE = ("classification", "operations", "egress", "destructive", "sensitive_source",
              "untrusted_input", "executing_principal", "phase", "target_scope")
BOOLEAN_FIELDS = ("egress", "destructive", "sensitive_source", "untrusted_input")
VALID_OPERATIONS = ("READ", "CREATE", "UPDATE", "DELETE", "EXECUTE", "PUBLISH", "TRANSMIT")
#: primary class derived from declared operations when only ``operations`` is given.
#: TRANSMIT is checked last: a tool that reads and sends is a READ with egress,
#: not a write of the resource it reads.
_OPS_TO_PRIMARY = (("EXECUTE", Operation.EXEC), ("DELETE", Operation.DELETE), ("CREATE", Operation.WRITE),
                   ("UPDATE", Operation.WRITE), ("PUBLISH", Operation.WRITE), ("READ", Operation.READ),
                   ("TRANSMIT", Operation.WRITE))


def _tool_keys(server_name: str, component_id: str, tool_name: str) -> List[str]:
    """Profile ``capabilities`` keys for one tool, least specific first."""
    keys = [tool_name, f"*/{tool_name}"]
    for owner in (component_id, server_name):
        if owner:
            keys.append(f"{owner}/*")
    for owner in (component_id, server_name):
        if owner:
            keys.append(f"{owner}/{tool_name}")
    seen: List[str] = []
    for k in keys:
        if k not in seen:
            seen.append(k)
    return seen


def declaration_for(server: ServerRecord, tool: ToolRecord, profile: Optional[Dict[str, Any]] = None,
                    source_declared: Optional[Dict[str, Any]] = None) -> Tuple[Dict[str, Any], str, List[str]]:
    """Merge the config-, source- and profile-level declarations for one tool.

    Returns ``(values, origin, problems)``.  Later sources overwrite earlier ones:
    config < source registry < profile - the profile is the auditor's own input,
    written for this run, and the config is the oldest statement about the tool.
    """
    problems: List[str] = []
    values: Dict[str, Any] = {}
    origins: List[str] = []

    from_config = dict(tool.definition.declared or {})
    if from_config:
        origins.append("config")
        values.update(from_config)

    if source_declared:
        origins.append("source")
        values.update(source_declared)

    caps = (profile or {}).get("capabilities") or {}
    if caps and not isinstance(caps, dict):
        problems.append("profile.capabilities must be an object of 'server/tool' -> declaration")
        caps = {}
    matched = False
    for key in _tool_keys(server.name, server.component_id, tool.name):
        entry = caps.get(key)
        if entry is None:
            continue
        if not isinstance(entry, dict):
            problems.append(f"profile.capabilities[{key}] must be an object")
            continue
        matched = True
        values.update(entry)
    if matched:
        origins.append("profile")

    clean: Dict[str, Any] = {}
    for key, value in values.items():
        if key not in DECLARABLE:
            problems.append(f"unknown declared property {key!r} (known: {', '.join(DECLARABLE)})")
            continue
        clean[key] = value
    return clean, "+".join(origins), problems


def _coerce(values: Dict[str, Any]) -> Tuple[Dict[str, Any], List[str]]:
    out: Dict[str, Any] = {}
    problems: List[str] = []
    if "classification" in values:
        raw = str(values["classification"]).upper()
        try:
            out["classification"] = Operation(raw)
        except ValueError:
            problems.append(f"classification {values['classification']!r} is not one of "
                            f"{[o.value for o in Operation]}")
    if "operations" in values:
        raw_ops = values["operations"]
        if not isinstance(raw_ops, list):
            problems.append("operations must be a list")
        else:
            ops: List[str] = []
            for op in raw_ops:
                name = str(op).upper()
                if name not in VALID_OPERATIONS:
                    problems.append(f"operation {op!r} is not one of {list(VALID_OPERATIONS)}")
                    continue
                if name not in ops:
                    ops.append(name)
            out["operations"] = ops
    for key in BOOLEAN_FIELDS:
        if key in values:
            if isinstance(values[key], bool):
                out[key] = values[key]
            else:
                problems.append(f"{key} must be true or false")
    for key in ("executing_principal", "phase"):
        if key in values:
            out[key] = str(values[key])
    if "target_scope" in values:
        if isinstance(values["target_scope"], dict):
            out["target_scope"] = dict(values["target_scope"])
        else:
            problems.append("target_scope must be an object")
    return out, problems


def _primary_from_operations(ops: List[str]) -> Operation:
    for name, op in _OPS_TO_PRIMARY:
        if name in ops:
            return op
    return Operation.UNKNOWN


def _annotation_conflicts(tool: ToolRecord, declared: Dict[str, Any]) -> List[Dict[str, Any]]:
    ann = tool.definition.annotations or {}
    conflicts: List[Dict[str, Any]] = []
    writes = {"CREATE", "UPDATE", "DELETE", "EXECUTE", "PUBLISH"}
    if ann.get("readOnlyHint") is True:
        declared_ops = set(declared.get("operations") or [])
        primary = declared.get("classification")
        if declared_ops & writes or (primary is not None and primary not in (Operation.READ, Operation.UNKNOWN)):
            conflicts.append({"property": "read_only", "annotation": "readOnlyHint=true",
                              "declared": sorted(declared_ops) or (primary.value if primary else None)})
    if "destructive" in declared and isinstance(ann.get("destructiveHint"), bool) \
            and ann["destructiveHint"] != declared["destructive"]:
        conflicts.append({"property": "destructive", "annotation": f"destructiveHint={str(ann['destructiveHint']).lower()}",
                          "declared": declared["destructive"]})
    return conflicts


def apply_declaration(tool: ToolRecord, values: Dict[str, Any], origin: str = "declared",
                      problems: Optional[List[str]] = None) -> List[str]:
    """Overlay a declaration on the heuristic result.  Returns the problems found."""
    declared, coercion_problems = _coerce(values)
    problems = list(problems or []) + coercion_problems
    if not declared:
        if problems:
            tool.provenance["declaration_problems"] = "; ".join(problems)
        return problems

    if "classification" in declared:
        tool.classification = declared["classification"]
    elif "operations" in declared:
        tool.classification = _primary_from_operations(declared["operations"])

    if "operations" in declared:
        tool.operations = list(declared["operations"])
    elif "classification" in declared:
        from ..models import PRIMARY_TO_OPS
        tool.operations = list(PRIMARY_TO_OPS[tool.classification])

    if "egress" in declared:
        tool.egress = declared["egress"]
        if not declared["egress"] and "operations" not in declared:
            # the heuristic adds TRANSMIT only because it suspected egress
            tool.operations = [o for o in tool.operations if o != "TRANSMIT"]
    for key in ("destructive", "sensitive_source", "untrusted_input"):
        if key in declared:
            setattr(tool, key, declared[key])
    for key in ("executing_principal", "phase"):
        if key in declared:
            setattr(tool, key, declared[key])
            tool.provenance[key] = f"declared({origin})"
    if "target_scope" in declared:
        tool.target_scope = declared["target_scope"]
    if tool.egress and "TRANSMIT" not in tool.operations:
        tool.operations.append("TRANSMIT")

    tool.classification_basis = "declared"
    tool.provenance["classification"] = f"declared:{origin}"
    tool.provenance["declared_fields"] = ", ".join(sorted(declared))
    # a declaration is a statement of the config/profile author, not an observation
    tool.knowledge_state = KnowledgeState.ASSUMED if tool.classification != Operation.UNKNOWN else KnowledgeState.UNKNOWN

    conflicts = _annotation_conflicts(tool, declared)
    if conflicts:
        tool.contract["declaration_vs_annotation"] = conflicts
        tool.knowledge_state = KnowledgeState.CONTRADICTORY
        tool.provenance["classification_conflict"] = (
            "declaration disagrees with the server's own annotation (self-report); "
            "the declaration is used and the disagreement is recorded, not resolved")
    if problems:
        tool.provenance["declaration_problems"] = "; ".join(problems)
    return problems
