"""Definition hasher: canonical hash of (name, title, description, schemas, annotations).

The canonicalization is versioned (``CANONICALIZATION_VERSION``): a change of
the algorithm must never look like a change of the target (TZ §17, §19).
A changed hash between snapshots is *drift*; whether it is a rug pull needs
approval state and impact evidence.
"""
from __future__ import annotations

import hashlib
import json
from typing import Dict, List

from ..models import ServerRecord, ToolDefinition

CANONICALIZATION_VERSION = "2"


def _canonical(obj: object) -> str:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def definition_hash(tool: ToolDefinition) -> str:
    payload = {
        "canon": CANONICALIZATION_VERSION,
        "name": tool.name,
        "title": tool.title,
        "description": tool.description,
        "inputSchema": tool.input_schema,
        "outputSchema": tool.output_schema,
        "annotations": tool.annotations,
    }
    return f"sha256:c{CANONICALIZATION_VERSION}:" + hashlib.sha256(_canonical(payload).encode("utf-8")).hexdigest()


def server_instructions_hash(server: ServerRecord) -> str:
    text = server.handshake.instructions or ""
    return f"sha256:c{CANONICALIZATION_VERSION}:" + hashlib.sha256(text.encode("utf-8")).hexdigest()


def build_hash_baseline(servers: List[ServerRecord]) -> Dict[str, str]:
    """``{"server/tool": hash, "server/@instructions": hash}``."""
    baseline: Dict[str, str] = {}
    for s in servers:
        for t in s.tools:
            t.definition_hash = definition_hash(t.definition)
            baseline[f"{s.name}/{t.name}"] = t.definition_hash
        if s.handshake.instructions:
            baseline[f"{s.name}/@instructions"] = server_instructions_hash(s)
    return baseline
