"""Definition hasher: canonical hash of (description + schema + annotations).

The hash is the rug-pull baseline for P8: a changed hash between audits
means the server changed a definition after it was approved.
"""
from __future__ import annotations

import hashlib
import json
from typing import Dict, List

from ..models import ServerRecord, ToolDefinition


def _canonical(obj: object) -> str:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def definition_hash(tool: ToolDefinition) -> str:
    payload = {
        "name": tool.name,
        "title": tool.title,
        "description": tool.description,
        "inputSchema": tool.input_schema,
        "outputSchema": tool.output_schema,
        "annotations": tool.annotations,
    }
    return "sha256:" + hashlib.sha256(_canonical(payload).encode("utf-8")).hexdigest()


def server_instructions_hash(server: ServerRecord) -> str:
    text = server.handshake.instructions or ""
    return "sha256:" + hashlib.sha256(text.encode("utf-8")).hexdigest()


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
