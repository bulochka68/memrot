"""Source snapshot adapter: native functions, background jobs, memory writes,
authorization transitions and token validation, read from a source tree or
from a pre-extracted facts file.

The adapter never executes code.  It uses ``ast`` to find declarations and
symbols and regular expressions (declared by the *profile*) to confirm that a
declared flow really exists in the build.  A profile declares *where to look
and what to expect*; the adapter reports what it found:

* ``static_supported`` - the symbol exists and every expected pattern matched;
* ``contradicted``     - the symbol exists but an expected pattern is missing
                          (or a negated pattern is present);
* ``unknown``          - the file or symbol is not available.

It does not assume that a function name determines its side effects (TZ §5.3).
"""
from __future__ import annotations

import ast
import hashlib
import json
import os
import re
import time
from typing import Any, Dict, List, Optional, Tuple

from ..models import AuditDocument, Component, KnowledgeState, Method, SourceType, digest as _digest
from ..evidence import EvidenceStore, bound_fragment
from .base import Adapter, AdapterResult
from .registry import register

FACTS_SCHEMA = "source-facts"
FACTS_VERSION = "1.0"

_TYPE_MAP = {"str": "string", "int": "integer", "float": "number", "bool": "boolean",
             "list": "array", "List": "array", "dict": "object", "Dict": "object", "Any": None}


def _dotted(node: ast.AST) -> Optional[str]:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        base = _dotted(node.value)
        return f"{base}.{node.attr}" if base else node.attr
    return None


def _annotation_to_schema(ann: Optional[ast.AST]) -> Tuple[Dict[str, Any], bool]:
    """Return (schema fragment, optional?) for a parameter annotation."""
    if ann is None:
        return {}, False
    text = ast.unparse(ann)
    optional = False
    if isinstance(ann, ast.BinOp) and isinstance(ann.op, ast.BitOr):      # X | None
        parts = [ast.unparse(ann.left), ast.unparse(ann.right)]
        optional = "None" in parts
        inner = [p for p in parts if p != "None"]
        text = inner[0] if inner else "Any"
    m = re.match(r"^(?:typing\.)?Optional\[(.+)\]$", text)
    if m:
        optional = True
        text = m.group(1)
    m = re.match(r"^(?:typing\.)?(List|list)\[(.+)\]$", text)
    if m:
        item = _TYPE_MAP.get(m.group(2).strip())
        schema: Dict[str, Any] = {"type": "array"}
        if item:
            schema["items"] = {"type": item}
        schema["python_annotation"] = ast.unparse(ann)
        return schema, optional
    t = _TYPE_MAP.get(text)
    schema = {"type": t} if t else {}
    schema["python_annotation"] = ast.unparse(ann)
    return schema, optional


def _const_value(node: Optional[ast.AST], module_consts: Dict[str, Any]) -> Optional[str]:
    if node is None:
        return None
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value
    if isinstance(node, ast.Name) and node.id in module_consts:
        return module_consts[node.id]
    if isinstance(node, ast.JoinedStr):
        return ast.unparse(node)
    return None


class SourceScanner:
    def __init__(self, root: str):
        self.root = os.path.abspath(root)
        self._cache: Dict[str, Tuple[str, ast.AST]] = {}

    def has(self, rel: str) -> bool:
        return os.path.isfile(os.path.join(self.root, rel))

    def read(self, rel: str) -> Tuple[str, ast.AST]:
        if rel in self._cache:
            return self._cache[rel]
        with open(os.path.join(self.root, rel), "r", encoding="utf-8", errors="replace") as fh:
            text = fh.read()
        tree = ast.parse(text) if rel.endswith(".py") else ast.Module(body=[], type_ignores=[])
        self._cache[rel] = (text, tree)
        return text, tree

    def file_digest(self, rel: str) -> str:
        with open(os.path.join(self.root, rel), "rb") as fh:
            return "sha256:" + hashlib.sha256(fh.read()).hexdigest()

    def module_consts(self, tree: ast.AST) -> Dict[str, str]:
        consts: Dict[str, str] = {}
        for node in getattr(tree, "body", []):
            if isinstance(node, ast.Assign) and len(node.targets) == 1 and isinstance(node.targets[0], ast.Name):
                if isinstance(node.value, ast.Constant) and isinstance(node.value.value, str):
                    consts[node.targets[0].id] = node.value.value
        return consts

    def symbol(self, rel: str, symbol: Optional[str]) -> Optional[Dict[str, Any]]:
        """Locate ``symbol`` (``func`` or ``Class.method``) and return its source slice."""
        text, tree = self.read(rel)
        lines = text.splitlines()
        if not symbol:
            return {"lineno": 1, "end_lineno": len(lines), "source": text}
        parts = symbol.split(".")
        scope: Any = tree
        node = None
        for part in parts:
            node = None
            for child in ast.iter_child_nodes(scope):
                if isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)) and child.name == part:
                    node = child
                    break
                if isinstance(child, ast.Assign) and any(isinstance(t, ast.Name) and t.id == part for t in child.targets):
                    node = child
                    break
            if node is None:
                return None
            scope = node
        src = "\n".join(lines[node.lineno - 1: node.end_lineno])
        return {"lineno": node.lineno, "end_lineno": node.end_lineno, "source": src}

    def tool_declarations(self, rel: str, decorator: str = "tool") -> List[Dict[str, Any]]:
        text, tree = self.read(rel)
        consts = self.module_consts(tree)
        out: List[Dict[str, Any]] = []
        for node in ast.walk(tree):
            if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                continue
            for dec in node.decorator_list:
                target = dec.func if isinstance(dec, ast.Call) else dec
                dotted = _dotted(target)
                if not dotted or dotted.split(".")[-1] != decorator.split(".")[-1]:
                    continue
                if "." in decorator and dotted != decorator:
                    continue
                name = node.name
                description = None
                if isinstance(dec, ast.Call):
                    for kw in dec.keywords:
                        if kw.arg == "name":
                            name = _const_value(kw.value, consts) or name
                        if kw.arg == "description":
                            description = _const_value(kw.value, consts)
                doc = ast.get_docstring(node) or ""
                props: Dict[str, Any] = {}
                required: List[str] = []
                args = node.args
                positional = args.posonlyargs + args.args
                defaults = [None] * (len(positional) - len(args.defaults)) + list(args.defaults)
                for a, d in zip(positional, defaults):
                    if a.arg in ("self", "cls"):
                        continue
                    ann_text = ast.unparse(a.annotation) if a.annotation is not None else ""
                    if ann_text.endswith("Context") or a.arg == "ctx":
                        continue
                    schema, optional = _annotation_to_schema(a.annotation)
                    props[a.arg] = schema
                    if d is None and not optional:
                        required.append(a.arg)
                for a, d in zip(args.kwonlyargs, args.kw_defaults):
                    ann_text = ast.unparse(a.annotation) if a.annotation is not None else ""
                    if ann_text.endswith("Context"):
                        continue
                    schema, optional = _annotation_to_schema(a.annotation)
                    props[a.arg] = schema
                    if d is None and not optional:
                        required.append(a.arg)
                src = "\n".join(text.splitlines()[node.lineno - 1: node.end_lineno])
                out.append({
                    "name": name, "function": node.name, "decorator": dotted, "path": rel,
                    "lineno": node.lineno, "end_lineno": node.end_lineno,
                    "description": description if description is not None else doc,
                    "docstring": doc,
                    "input_schema": {"type": "object", "properties": props, "required": required},
                    "digest": "sha256:" + hashlib.sha256(src.encode("utf-8")).hexdigest(),
                    "is_async": isinstance(node, ast.AsyncFunctionDef),
                })
                break
        return out


def _check_patterns(source: str, patterns: List[str], negate: List[str]) -> Tuple[bool, Dict[str, Any]]:
    matched: Dict[str, Any] = {"present": [], "missing": [], "unexpected": []}
    ok = True
    for p in patterns or []:
        m = re.search(p, source, re.M)
        if m:
            matched["present"].append({"pattern": p, "fragment": bound_fragment(m.group(0), 200)})
        else:
            matched["missing"].append(p)
            ok = False
    for p in negate or []:
        m = re.search(p, source, re.M)
        if m:
            matched["unexpected"].append({"pattern": p, "fragment": bound_fragment(m.group(0), 200)})
            ok = False
    return ok, matched


def extract_facts(root: str, spec: Dict[str, Any], captured_from: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    """Produce the portable facts file from a source tree and a profile ``source_facts`` spec."""
    sc = SourceScanner(root)
    facts: Dict[str, Any] = {
        "schema": FACTS_SCHEMA, "version": FACTS_VERSION,
        "captured_from": {"root": os.path.relpath(root), "captured_at": time.time(), "method": "ast+regex scan",
                          **(captured_from or {})},
        "files": {}, "tool_declarations": [], "flows": [], "auth_transitions": [], "token_validation": [],
        "background_jobs": [], "break_points": [], "components": [],
    }

    def file_meta(rel: str) -> bool:
        if rel in facts["files"]:
            return facts["files"][rel]["present"]
        present = sc.has(rel)
        facts["files"][rel] = {"present": present, "sha256": sc.file_digest(rel) if present else None}
        return present

    for decl in spec.get("tool_declarations") or []:
        rel = decl["path"]
        if not file_meta(rel):
            facts["tool_declarations"].append({"component": decl.get("component"), "path": rel, "status": "unknown",
                                               "reason": "file not available"})
            continue
        for d in sc.tool_declarations(rel, decl.get("decorator", "tool")):
            d.update({"component": decl.get("component"), "kind": decl.get("kind", "mcp"), "status": "static_supported"})
            facts["tool_declarations"].append(d)

    def verify(item: Dict[str, Any], group: str) -> Dict[str, Any]:
        rel = item.get("path")
        out = dict(item)
        out["group"] = group
        if not rel or not file_meta(rel):
            out.update({"status": "unknown", "reason": f"source file not available: {rel}"})
            return out
        sym = sc.symbol(rel, item.get("symbol"))
        if sym is None:
            out.update({"status": "unknown", "reason": f"symbol {item.get('symbol')!r} not found in {rel}"})
            return out
        ok, matched = _check_patterns(sym["source"], item.get("patterns") or [], item.get("negate_patterns") or [])
        out["status"] = "static_supported" if ok else "contradicted"
        out["matched"] = matched
        out["evidence"] = {
            "source_type": "source_code", "method": "static_analysis",
            "locator": {"path": rel, "symbol": item.get("symbol"), "lines": [sym["lineno"], sym["end_lineno"]]},
            "digest": "sha256:" + hashlib.sha256(sym["source"].encode("utf-8")).hexdigest(),
            "fragment": bound_fragment(sym["source"], 600),
            "summary": item.get("statement") or item.get("id") or f"{rel}:{item.get('symbol')}",
        }
        return out

    for item in spec.get("flows") or []:
        facts["flows"].append(verify(item, "flow"))
    for item in spec.get("auth_transitions") or []:
        facts["auth_transitions"].append(verify(item, "auth_transition"))
    for item in spec.get("background_jobs") or []:
        facts["background_jobs"].append(verify(item, "background_job"))
    for item in spec.get("break_points") or []:
        facts["break_points"].append(verify(item, "break_point"))
    for item in spec.get("token_validation") or []:
        v = verify({k: val for k, val in item.items() if k != "checks"}, "token_validation")
        observed: Dict[str, Any] = {}
        if v.get("status") != "unknown":
            sym = sc.symbol(item["path"], item.get("symbol")) or {"source": ""}
            for check, cfg in (item.get("checks") or {}).items():
                found = bool(re.search(cfg["pattern"], sym["source"], re.M)) if cfg.get("pattern") else None
                if found is None:
                    observed[check] = None
                elif found:
                    observed[check] = cfg.get("found_means", True)
                else:
                    observed[check] = cfg.get("absent_means", None)
        v["observed"] = observed
        facts["token_validation"].append(v)
    for comp in spec.get("components") or []:
        facts["components"].append(comp)
    return facts


@register
class SourceSnapshotAdapter(Adapter):
    kind = "source_snapshot"
    adapter_version = "2.0.0"
    supported = ["python_tool_declarations(ast)", "symbol_lookup", "profile_flow_verification(regex)",
                 "token_validation_config", "background_jobs", "break_points", "pre_extracted_facts"]
    unsupported = {
        "side_effect_inference": "a function name does not define its side effects; flows come from the profile and are verified, not inferred",
        "non_python": "only Python sources are parsed; other files are digested only",
        "execution": "code is never executed",
    }

    def collect(self, doc: AuditDocument, store: EvidenceStore) -> AdapterResult:
        spec = dict(doc.profile.get("source_facts") or {})
        facts_path = self.binding.path("path")
        root = self.binding.path("root")
        if facts_path and os.path.isfile(facts_path):
            facts = self._read_json(facts_path)
            if facts.get("schema") != FACTS_SCHEMA:
                return AdapterResult(self.status("unavailable", [f"{facts_path}: not a {FACTS_SCHEMA} file"]))
        elif root and os.path.isdir(root):
            facts = extract_facts(root, spec, captured_from=self.binding.binding.get("captured_from"))
        else:
            return AdapterResult(self.status("unavailable", ["neither a facts file nor a source root is available"]))

        count = 0
        unknown = 0
        # register evidence for every verified item so ids are stable across scan / replay
        for group in ("flows", "auth_transitions", "background_jobs", "break_points", "token_validation"):
            for item in facts.get(group) or []:
                ev_desc = item.get("evidence")
                if item.get("status") == "unknown" or not ev_desc:
                    unknown += 1
                    item["evidence_refs"] = []
                    continue
                ev = store.add(SourceType.SOURCE_CODE, Method.STATIC_ANALYSIS, ev_desc["locator"],
                               digest=ev_desc.get("digest"), fragment=ev_desc.get("fragment"),
                               summary=ev_desc.get("summary", ""), adapter=self.kind,
                               adapter_version=self.adapter_version,
                               captured_at=(facts.get("captured_from") or {}).get("captured_at"),
                               scope={"build_ref": (facts.get("captured_from") or {}).get("commit") or doc.target.get("build_ref")})
                item["evidence_refs"] = [ev.evidence_id]
                count += 1
        for d in facts.get("tool_declarations") or []:
            if d.get("status") == "unknown":
                unknown += 1
                continue
            ev = store.add(SourceType.SOURCE_CODE, Method.STATIC_ANALYSIS,
                           {"path": d["path"], "symbol": d.get("function"), "lines": [d.get("lineno"), d.get("end_lineno")],
                            "declaration": d["name"]},
                           digest=d.get("digest"), summary=f"tool declaration {d['name']} ({d.get('decorator')})",
                           adapter=self.kind, adapter_version=self.adapter_version,
                           captured_at=(facts.get("captured_from") or {}).get("captured_at"),
                           scope={"build_ref": (facts.get("captured_from") or {}).get("commit") or doc.target.get("build_ref")})
            d["evidence_refs"] = [ev.evidence_id]
            count += 1
        for comp in facts.get("components") or []:
            doc.components.append(Component(
                component_id=comp["id"], type=comp.get("type", "unknown"), name=comp.get("name", comp["id"]),
                role=comp.get("role", ""), inventory_sources=["source_defined"],
                attributes={k: v for k, v in comp.items() if k not in ("id", "type", "name", "role")},
                knowledge_state=KnowledgeState.KNOWN,
            ))
        doc.source_facts = facts
        state = "available" if count and not unknown else ("partial" if count else "unavailable")
        reasons = []
        if unknown:
            reasons.append(f"{unknown} declared item(s) could not be located in the available sources")
        return AdapterResult(self.status(state, reasons, captured_at=(facts.get("captured_from") or {}).get("captured_at"),
                                         evidence_count=count), facts={"facts_path": facts_path, "root": root})
