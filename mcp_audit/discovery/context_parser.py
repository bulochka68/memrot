"""Agent-context parser.

Context files (CLAUDE.md, .cursorrules, copilot-instructions.md, AGENTS.md ...)
are not tools, but they are instructions the agent obeys, so they are part of
the attack surface.  They get the same definition-plane lint as tool
descriptions.  Their content is *data under audit*: it never becomes auditor
policy, never changes scope, settings or the baseline (TZ §14.6, §19).
"""
from __future__ import annotations

import hashlib
import os
from typing import Iterable, List, Optional

from ..models import ContextFile

CONTEXT_FILE_KINDS = {
    "CLAUDE.md": "claude_md",
    "CLAUDE.local.md": "claude_md",
    "AGENTS.md": "agents_md",
    "GEMINI.md": "gemini_md",
    ".cursorrules": "cursorrules",
    ".windsurfrules": "windsurfrules",
    ".clinerules": "clinerules",
    "copilot-instructions.md": "copilot_instructions",
    ".mcp.json": "mcp_config",
}
SOURCE_ROLES = {"mcp_config": "mcp_config"}
CONTEXT_DIRS = (".cursor/rules", ".claude", ".github", ".claude/commands", ".claude/agents", ".claude/skills")
MAX_CONTEXT_BYTES = 512 * 1024


def _kind_for(path: str) -> Optional[str]:
    base = os.path.basename(path)
    if base in CONTEXT_FILE_KINDS:
        return CONTEXT_FILE_KINDS[base]
    parts = path.replace("\\", "/").split("/")
    if ".cursor" in parts and base.endswith((".mdc", ".md")):
        return "cursor_rule"
    if ".claude" in parts and base.endswith(".md"):
        return "claude_instruction"
    return None


def discover_context_files(root: str, max_depth: int = 3, extra: Iterable[str] = ()) -> List[str]:
    """Walk ``root`` (bounded depth) and collect agent instruction files."""
    found: List[str] = []
    root = os.path.abspath(root)
    base_depth = root.rstrip(os.sep).count(os.sep)
    for dirpath, dirnames, filenames in os.walk(root):
        depth = dirpath.count(os.sep) - base_depth
        dirnames[:] = [d for d in dirnames if d not in ("node_modules", ".git", "venv", ".venv", "__pycache__", "dist", "build")]
        if depth >= max_depth:
            dirnames[:] = [d for d in dirnames if d in (".claude", ".cursor", ".github")]
        for fn in filenames:
            p = os.path.join(dirpath, fn)
            if _kind_for(p):
                found.append(p)
    for p in extra:
        if os.path.isfile(p) and p not in found:
            found.append(os.path.abspath(p))
    return sorted(found)


def parse_context_file(path: str) -> ContextFile:
    with open(path, "rb") as fh:
        data = fh.read(MAX_CONTEXT_BYTES + 1)
    truncated = len(data) > MAX_CONTEXT_BYTES
    data = data[:MAX_CONTEXT_BYTES]
    kind = _kind_for(path) or "unknown"
    cf = ContextFile(
        path=path, kind=kind, size=os.path.getsize(path), sha256=hashlib.sha256(data).hexdigest(),
        source_role=SOURCE_ROLES.get(kind, "agent_instructions"), truncated=truncated,
    )
    cf.text = data.decode("utf-8", "replace")
    return cf
