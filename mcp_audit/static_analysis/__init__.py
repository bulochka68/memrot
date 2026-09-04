"""Layer 2 - Static analysis of the *definition plane*.

Tool descriptions and schemas are untrusted payload, not "text from the
developer".  This layer finds tool poisoning before anything executes and
produces the hash baseline used by drift detection (P8 rug-pull alerts).
"""
from .description_linter import lint_text, lint_tool
from .schema_analyzer import analyze_schema
from .collision_detector import detect_collisions
from .hasher import definition_hash, build_hash_baseline
from .mcp_scan import run_mcp_scan
from .runner import run_static_analysis

__all__ = [
    "lint_text", "lint_tool", "analyze_schema", "detect_collisions",
    "definition_hash", "build_hash_baseline", "run_mcp_scan", "run_static_analysis",
]
