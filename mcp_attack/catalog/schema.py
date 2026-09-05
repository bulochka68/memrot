"""Hand-rolled catalog validation (no jsonschema dependency), mirroring
``mcp_audit``'s own hand-rolled validators rather than pulling in a schema
library for a shape this small and this stable."""
from __future__ import annotations

import json
from typing import Any, Dict, List

from ..models import FRAMING_VALUES, LAYER_VALUES, PAYLOAD_VALUES, PROPAGATION_VALUES

REQUIRED_FIELDS = ("id", "title", "framing", "payload", "layer", "propagation", "probe", "rule_ids")
ALLOWED_FRAMING = set(FRAMING_VALUES)
ALLOWED_PAYLOAD = set(PAYLOAD_VALUES)
ALLOWED_LAYER = set(LAYER_VALUES)
ALLOWED_PROPAGATION = set(PROPAGATION_VALUES)
ALLOWED_ACCESS_PROFILE = {"black_box", "grey_box", "white_box"}


def validate_variant_dict(d: Dict[str, Any], where: str = "") -> List[str]:
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

    propagation = d.get("propagation")
    inject_turns = d.get("inject_turns") or []
    canary_template = d.get("canary_template") or ""
    if propagation in ("cross-user", "cross-session-same-user"):
        if not inject_turns:
            errors.append(f"{tag}propagation={propagation!r} requires non-empty inject_turns")
        if not canary_template:
            errors.append(f"{tag}propagation={propagation!r} requires a canary_template")
        if "{canary}" not in canary_template and canary_template:
            errors.append(f"{tag}canary_template must contain the '{{canary}}' placeholder")
    elif propagation == "single-turn":
        if inject_turns:
            errors.append(f"{tag}propagation='single-turn' must not carry inject_turns (the ask lives in probe)")

    if not isinstance(d.get("rule_ids", []), list):
        errors.append(f"{tag}rule_ids must be a list")
    if not isinstance(d.get("taxonomy", []), list):
        errors.append(f"{tag}taxonomy must be a list")

    return errors


def validate_catalog_file(path: str) -> List[str]:
    try:
        with open(path, "r", encoding="utf-8") as fh:
            data = json.load(fh)
    except (OSError, json.JSONDecodeError) as exc:
        return [f"{path}: cannot read/parse: {exc}"]
    if not isinstance(data, dict) or "variants" not in data:
        return [f"{path}: expected an object with a 'variants' list"]
    variants = data["variants"]
    if not isinstance(variants, list):
        return [f"{path}: 'variants' must be a list"]
    errors: List[str] = []
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
        errors.extend(validate_variant_dict(v, where=where))
    return errors
