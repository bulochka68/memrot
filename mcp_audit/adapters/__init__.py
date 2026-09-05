"""Source adapters (TZ §5.3): MCP, source, policy, memory, trace, deployment, fixtures."""
from .base import Adapter, AdapterBinding, AdapterResult
from .registry import register, get_adapter, known_kinds, build
from . import mcp_inventory, source_snapshot, policy_snapshot, memory_events, trace, deployment, control_fixtures  # noqa: F401

# Which rules need which adapter kinds (used by the applicability plan).
SOURCE_KINDS = {
    "mcp_inventory": "inventory (config / snapshot / live)",
    "source_snapshot": "application source facts",
    "policy_snapshot": "expected access & memory policy",
    "memory_event_snapshot": "memory records and events",
    "trace": "runtime trace",
    "deployment": "deployment snapshot",
    "control_fixtures": "registered control fixtures",
}

__all__ = ["Adapter", "AdapterBinding", "AdapterResult", "register", "get_adapter", "known_kinds", "build", "SOURCE_KINDS"]
