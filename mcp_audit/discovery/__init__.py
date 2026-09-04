"""Layer 1 - Discovery / Enumeration.

Builds the raw graph ``server -> tools -> schemas/descriptions -> transport``
from three inputs: MCP config files, a live MCP handshake, and the agent's
context files (CLAUDE.md, .cursorrules, copilot-instructions.md).
"""
from .config_parser import parse_config, load_config_file, parse_snapshot
from .introspector import Introspector, introspect_server
from .context_parser import discover_context_files, parse_context_file

__all__ = [
    "parse_config", "load_config_file", "parse_snapshot",
    "Introspector", "introspect_server",
    "discover_context_files", "parse_context_file",
]
