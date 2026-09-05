"""Import of audit v1.0 / v1.1 documents into the v2 model (TZ §18)."""
from .legacy import load_legacy_audit, import_legacy_dict, LEGACY_VERSIONS

__all__ = ["load_legacy_audit", "import_legacy_dict", "LEGACY_VERSIONS"]
