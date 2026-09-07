"""Hand-rolled catalog validation (no jsonschema dependency), mirroring
``mcp_audit``'s own hand-rolled validators rather than pulling in a schema
library for a shape this small and this stable."""
from __future__ import annotations

import json
from typing import Any, Dict, List

from ..models import (DELIVERY_CHANNEL_VALUES, DOMAIN_VALUES, FRAMING_VALUES, LAYER_VALUES,
                     PAYLOAD_VALUES, PROPAGATION_VALUES, THREAT_MODEL_VALUES, TOOL_VECTOR_VALUES)
from ..taxonomy import ATTACK_TECHNIQUE_CATEGORY_SLUGS, OWASP_AMG_CATEGORY_SLUGS

REQUIRED_FIELDS = ("id", "title", "framing", "payload", "layer", "propagation", "probe", "rule_ids")
ALLOWED_FRAMING = set(FRAMING_VALUES)
ALLOWED_PAYLOAD = set(PAYLOAD_VALUES)
ALLOWED_LAYER = set(LAYER_VALUES)
ALLOWED_PROPAGATION = set(PROPAGATION_VALUES)
ALLOWED_ACCESS_PROFILE = {"black_box", "grey_box", "white_box"}
ALLOWED_OWASP_AMG_CATEGORY = set(OWASP_AMG_CATEGORY_SLUGS)
ALLOWED_TECHNIQUE_CATEGORY = set(ATTACK_TECHNIQUE_CATEGORY_SLUGS)
ALLOWED_DELIVERY_CHANNEL = set(DELIVERY_CHANNEL_VALUES)
ALLOWED_THREAT_MODEL = set(THREAT_MODEL_VALUES)
ALLOWED_TOOL_VECTOR = set(TOOL_VECTOR_VALUES)
ALLOWED_DOMAIN = set(DOMAIN_VALUES)


def _is_benign_control(d: Dict[str, Any]) -> bool:
    return d.get("framing") == "none" and d.get("payload") == "none"


def validate_variant_dict(d: Dict[str, Any], where: str = "", *,
                          require_taxonomy: bool = False) -> List[str]:
    errors: List[str] = []
    tag = f"{where}: " if where else ""
    for field_name in REQUIRED_FIELDS:
        if field_name not in d or d[field_name] in (None, ""):
            if field_name == "rule_ids" and d.get("rule_ids") == []:
                continue   # benign_control variants legitimately carry no rule tag
            errors.append(f"{tag}missing required field {field_name!r}")

    def check_enum(field_name: str, allowed: set) -> None:
        v = d.get(field_name)
        if v is not None and v not in allowed:
            errors.append(f"{tag}{field_name}={v!r} not in {sorted(allowed)}")

    check_enum("framing", ALLOWED_FRAMING)
    check_enum("payload", ALLOWED_PAYLOAD)
    check_enum("layer", ALLOWED_LAYER)
    check_enum("propagation", ALLOWED_PROPAGATION)
    check_enum("access_profile_required", ALLOWED_ACCESS_PROFILE)

    owasp_amg_category = d.get("owasp_amg_category")
    if owasp_amg_category and owasp_amg_category not in ALLOWED_OWASP_AMG_CATEGORY:
        errors.append(f"{tag}owasp_amg_category={owasp_amg_category!r} not in {sorted(ALLOWED_OWASP_AMG_CATEGORY)}")

    technique_category = d.get("technique_category")
    if technique_category and technique_category not in ALLOWED_TECHNIQUE_CATEGORY:
        errors.append(f"{tag}technique_category={technique_category!r} not in {sorted(ALLOWED_TECHNIQUE_CATEGORY)}")

    domain = d.get("domain")
    if domain and domain not in ALLOWED_DOMAIN:
        errors.append(f"{tag}domain={domain!r} not in {sorted(ALLOWED_DOMAIN)}")

    check_enum("delivery_channel", ALLOWED_DELIVERY_CHANNEL)
    check_enum("threat_model", ALLOWED_THREAT_MODEL)

    delivery_channel = d.get("delivery_channel", "chat_direct")
    if delivery_channel == "tool_result":
        tool_stage = d.get("tool_stage")
        if not isinstance(tool_stage, dict) or not tool_stage.get("tool_name") or not tool_stage.get("content_template"):
            errors.append(f"{tag}delivery_channel='tool_result' requires tool_stage.tool_name and "
                          "tool_stage.content_template")
        else:
            if "{canary}" not in tool_stage["content_template"]:
                errors.append(f"{tag}tool_stage.content_template must contain the '{{canary}}' placeholder")
            vector = tool_stage.get("vector", "web_search")
            if vector not in ALLOWED_TOOL_VECTOR:
                errors.append(f"{tag}tool_stage.vector={vector!r} not in {sorted(ALLOWED_TOOL_VECTOR)}")
            if "persist" in tool_stage and not isinstance(tool_stage["persist"], bool):
                errors.append(f"{tag}tool_stage.persist must be a bool if present, got {tool_stage['persist']!r}")
        if not d.get("trigger_message"):
            errors.append(f"{tag}delivery_channel='tool_result' requires a non-empty trigger_message")

    if delivery_channel == "document_ingestion":
        inject_turns = d.get("inject_turns") or []
        if not inject_turns:
            errors.append(f"{tag}delivery_channel='document_ingestion' requires non-empty inject_turns "
                          "(the document body)")
        canary_template = d.get("canary_template") or ""
        if not canary_template:
            errors.append(f"{tag}delivery_channel='document_ingestion' requires a canary_template")
        elif "{canary}" not in canary_template:
            errors.append(f"{tag}canary_template must contain the '{{canary}}' placeholder")

    propagation = d.get("propagation")
    inject_turns = d.get("inject_turns") or []
    canary_template = d.get("canary_template") or ""
    if delivery_channel == "chat_direct" and propagation in ("cross-user", "cross-session-same-user"):
        if not inject_turns:
            errors.append(f"{tag}propagation={propagation!r} requires non-empty inject_turns")
        if not canary_template:
            errors.append(f"{tag}propagation={propagation!r} requires a canary_template")
        if "{canary}" not in canary_template and canary_template:
            errors.append(f"{tag}canary_template must contain the '{{canary}}' placeholder")
    elif delivery_channel == "chat_direct" and propagation == "single-turn":
        if inject_turns:
            errors.append(f"{tag}propagation='single-turn' must not carry inject_turns (the ask lives in probe)")

    if not isinstance(d.get("rule_ids", []), list):
        errors.append(f"{tag}rule_ids must be a list")
    if not isinstance(d.get("taxonomy", []), list):
        errors.append(f"{tag}taxonomy must be a list")

    if require_taxonomy and not _is_benign_control(d):
        threat_model = d.get("threat_model", "memory_poisoning")
        if threat_model == "memory_poisoning" and not (d.get("owasp_amg_category") or ""):
            errors.append(f"{tag}memory_poisoning variant must carry owasp_amg_category")
        has_atlas = bool(d.get("taxonomy") or [])
        has_technique = bool(d.get("technique_category") or "")
        if not has_atlas and not has_technique:
            errors.append(f"{tag}variant must carry taxonomy (ATLAS) or technique_category")

    return errors


def validate_catalog_file(path: str, *, require_taxonomy: bool = False) -> List[str]:
    try:
        with open(path, "r", encoding="utf-8") as fh:
            data = json.load(fh)
    except (OSError, json.JSONDecodeError) as exc:
        return [f"{path}: cannot read/parse: {exc}"]
    if not isinstance(data, dict) or "variants" not in data:
        return [f"{path}: expected an object with a 'variants' list"]
    domain = data.get("domain", "neutral")
    errors: List[str] = []
    if domain not in ALLOWED_DOMAIN:
        errors.append(f"{path}: domain={domain!r} not in {sorted(ALLOWED_DOMAIN)}")
    variants = data["variants"]
    if not isinstance(variants, list):
        return errors + [f"{path}: 'variants' must be a list"]
    seen_ids = set()
    for i, v in enumerate(variants):
        where = f"{path}#{i}"
        if not isinstance(v, dict):
            errors.append(f"{where}: variant must be an object")
            continue
        vid = v.get("id")
        if vid in seen_ids:
            errors.append(f"{where}: duplicate variant id {vid!r}")
        seen_ids.add(vid)
        errors.extend(validate_variant_dict(v, where=where, require_taxonomy=require_taxonomy))
    return errors
