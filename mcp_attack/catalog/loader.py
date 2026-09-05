from __future__ import annotations

import json
import os
from typing import Iterable, List

from ..models import AttackVariant
from .schema import validate_catalog_file


def discover_catalog_files(paths: Iterable[str]) -> List[str]:
    """Expand directories to the catalog.json files they contain -- a
    category folder directly (``prompts/mem02_.../catalog.json``), or a
    parent directory holding several category folders (recurses one or more
    levels to find every ``catalog.json`` under it). Individual *.json files
    are passed through unchanged."""
    out: List[str] = []
    for p in paths:
        if os.path.isdir(p):
            direct = os.path.join(p, "catalog.json")
            if os.path.isfile(direct):
                out.append(direct)
                continue
            found = []
            for dirpath, _dirnames, filenames in os.walk(p):
                if "catalog.json" in filenames:
                    found.append(os.path.join(dirpath, "catalog.json"))
            if found:
                out.extend(sorted(found))
                continue
            for name in sorted(os.listdir(p)):
                if name.endswith(".json"):
                    out.append(os.path.join(p, name))
        elif os.path.isfile(p):
            out.append(p)
        else:
            raise FileNotFoundError(f"catalog path not found: {p}")
    return out


def load_catalog(paths: Iterable[str], strict: bool = True) -> List[AttackVariant]:
    files = discover_catalog_files(paths)
    variants: List[AttackVariant] = []
    seen_ids = set()
    for path in files:
        errors = validate_catalog_file(path)
        if errors and strict:
            raise ValueError(f"catalog validation failed:\n" + "\n".join(errors))
        with open(path, "r", encoding="utf-8") as fh:
            data = json.load(fh)
        for v in data.get("variants", []):
            if v.get("id") in seen_ids:
                raise ValueError(f"{path}: duplicate variant id {v.get('id')!r} across catalog files")
            seen_ids.add(v.get("id"))
            variants.append(AttackVariant(
                id=v["id"], title=v.get("title", v["id"]), framing=v.get("framing", ""),
                payload=v.get("payload", ""), layer=v.get("layer", "none"),
                propagation=v.get("propagation", "single-turn"), probe=v.get("probe", ""),
                canary_template=v.get("canary_template", ""), inject_turns=list(v.get("inject_turns") or []),
                rule_ids=list(v.get("rule_ids") or []), taxonomy=list(v.get("taxonomy") or []),
                access_profile_required=v.get("access_profile_required", "black_box"),
                attacker_role=v.get("attacker_role", "attacker"), victim_role=v.get("victim_role", "victim"),
                attacker_principal=v.get("attacker_principal"), victim_principal=v.get("victim_principal"),
                target_ref=v.get("target_ref"), rule_semantic=v.get("rule_semantic"),
                source=v.get("source", "static_catalog"), notes=v.get("notes", ""),
            ))
    return variants
