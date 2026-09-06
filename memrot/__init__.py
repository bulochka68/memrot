"""memrot: multi-step attack harness for AI agent memory and tools.

Standalone package -- zero import dependency on ``mcp_audit``.  Alignment
with the auditor's vocabulary (rule ids such as ``MEM-02``, MITRE ATLAS
taxonomy ids) is by plain string tag only, via ``audit_bridge.py``, so this
package stays portable to any target that implements ``TargetAdapter``.
"""
from __future__ import annotations

ATTACK_ENGINE_VERSION = "1.0.0"
ATTACK_SCHEMA_VERSION = "1.0"
CATALOG_SCHEMA_VERSION = "1.0"

# CLI-facing product version/tagline (the banner) -- deliberately separate from
# ATTACK_ENGINE_VERSION, which tracks the engine/schema's own compatibility
# and is unrelated to how far along the product itself is.
MEMROT_VERSION = "0.1"
MEMROT_TAGLINE = "demo"
