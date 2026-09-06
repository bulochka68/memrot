"""A foreign-style MCP server: tools live in a module-level registry, not in decorators."""
from .palace import Palace

_palace = Palace()


def _mine_note(subject_id: str, text: str) -> dict:
    return _palace.mine_note(subject_id, text)


def _traverse(subject_id: str, query: str) -> list:
    return _palace.traverse(subject_id, query)


def _dissolve_wing(wing_id: str) -> dict:
    return _palace.dissolve_wing(wing_id)


def _build_generated_definition(name):
    return {"description": f"generated {name}", "input_schema": {"type": "object", "properties": {}}}


TOOLS = {
    "vault_mine_note": {
        "description": "Mine a note out of the working set and checkpoint it into the palace.",
        "input_schema": {"type": "object", "properties": {"subject_id": {"type": "string"},
                                                          "text": {"type": "string"}},
                         "required": ["subject_id", "text"]},
        "handler": _mine_note,
        "x_audit": {"operations": ["CREATE"], "egress": False, "sensitive_source": True},
    },
    "vault_traverse": {
        "description": "Traverse the palace hallways and return the drawers of a subject.",
        "input_schema": {"type": "object", "properties": {"subject_id": {"type": "string"},
                                                          "query": {"type": "string"}},
                         "required": ["subject_id"]},
        "handler": _traverse,
    },
    "vault_dissolve_wing": {
        "description": "Dissolve a whole wing of the palace.",
        "input_schema": {"type": "object", "properties": {"wing_id": {"type": "string"}}, "required": ["wing_id"]},
        "handler": _dissolve_wing,
    },
    "vault_generated": _build_generated_definition("vault_generated"),
}


# A second, list-shaped registry: the same stand does not have to be consistent with itself.
EXTRA_TOOLS = [
    {"name": "vault_hallway_map",
     "description": "Return the hallway map of the palace.",
     "input_schema": {"type": "object", "properties": {}}},
]
