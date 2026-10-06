"""Strict validation of a memory-trace event against the JSON schema.

Requires ``jsonschema>=4.21.1`` (correct ``$ref`` / ``$id`` resolution for a
schema loaded from a local path) and ``rfc3339-validator`` (without it
``jsonschema.FormatChecker`` silently skips ``format: date-time``).

All cross-field rules (``allOf``, ``if``/``then``) live in
``schemas/memory-trace-0.1.schema.json``; this module does not repeat them.
"""
from __future__ import annotations

import json
from functools import lru_cache
from pathlib import Path
from typing import Any, Dict, List

import jsonschema
from jsonschema.exceptions import ValidationError, best_match

SCHEMA_PATH = Path(__file__).resolve().parent.parent / "schemas" / "memory-trace-0.1.schema.json"


class SchemaValidationError(ValueError):
    """An event does not match the memory-trace schema.

    ``path`` is the JSON path of the offending field (``$.parent_event_refs[0]``);
    ``errors`` lists every violation found, most relevant first.
    """

    def __init__(self, path: str, message: str, errors: List[Dict[str, str]]) -> None:
        super().__init__(f"{path}: {message}")
        self.path = path
        self.message = message
        self.errors = errors


@lru_cache(maxsize=1)
def _validator() -> jsonschema.Draft7Validator:
    with open(SCHEMA_PATH, encoding="utf-8") as fh:
        schema = json.load(fh)
    jsonschema.Draft7Validator.check_schema(schema)
    # The default draft-7 checker has no "uuid" format; the generic one has every registered format.
    return jsonschema.Draft7Validator(schema, format_checker=jsonschema.FormatChecker())


def _field_path(error: ValidationError) -> str:
    """JSON path of the field itself, not of its parent object.

    ``required`` and ``additionalProperties`` are reported by jsonschema on the
    enclosing object; point at the missing / unexpected key instead.
    """
    base = error.json_path
    instance = error.instance
    if error.validator == "required" and isinstance(instance, dict):
        missing = [k for k in error.validator_value if k not in instance]
        if missing:
            return f"{base}.{missing[0]}"
    if error.validator == "additionalProperties" and isinstance(instance, dict):
        known = error.schema.get("properties", {})
        extra = [k for k in instance if k not in known]
        if extra:
            return f"{base}.{extra[0]}"
    return base


def validate_event(event: Dict[str, Any]) -> None:
    """Raise :class:`SchemaValidationError` unless ``event`` matches the schema."""
    errors = list(_validator().iter_errors(event))
    if not errors:
        return
    first = best_match(errors)
    ordered = [first] + [e for e in errors if e is not first]
    raise SchemaValidationError(
        _field_path(first),
        first.message,
        [{"path": _field_path(e), "message": e.message} for e in ordered],
    )
