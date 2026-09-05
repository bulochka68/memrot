"""Layer 2 - Static analysis of the definition plane (signals, contracts, collisions, hashes, reconciliation)."""
from .description_linter import lint_text, lint_tool
from .schema_analyzer import analyze_schema, compare_contracts
from .collision_detector import detect_collisions
from .hasher import definition_hash, build_hash_baseline, CANONICALIZATION_VERSION
from .mcp_scan import run_mcp_scan
from .reconcile import reconcile_inventory
from .runner import run_static_analysis

__all__ = ["lint_text", "lint_tool", "analyze_schema", "compare_contracts", "detect_collisions", "definition_hash",
           "build_hash_baseline", "CANONICALIZATION_VERSION", "run_mcp_scan", "reconcile_inventory", "run_static_analysis"]
