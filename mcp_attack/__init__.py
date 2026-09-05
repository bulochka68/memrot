"""mcp_attack: multi-step attack harness for AI agent memory and tools.

Standalone package -- zero import dependency on ``mcp_audit``.  Alignment
with the auditor's vocabulary (rule ids such as ``MEM-02``, MITRE ATLAS
taxonomy ids) is by plain string tag only, via ``audit_bridge.py``, so this
package stays portable to any target that implements ``TargetAdapter``.
"""
from __future__ import annotations

ATTACK_ENGINE_VERSION = "1.0.0"
ATTACK_SCHEMA_VERSION = "1.0"
CATALOG_SCHEMA_VERSION = "1.0"
