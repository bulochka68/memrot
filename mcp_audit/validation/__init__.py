"""Structural + semantic validation of the v2 report (TZ §15.1)."""
from .schema import validate_document, ValidationError, SCHEMA_PATH

__all__ = ["validate_document", "ValidationError", "SCHEMA_PATH"]
