import json
import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
EXAMPLES = os.path.join(ROOT, "examples")
FIXTURES = os.path.join(ROOT, "tests", "fixtures")


@pytest.fixture(scope="session")
def stand_doc():
    """The stand example evaluated once per session (offline, snapshots only)."""
    from mcp_audit.orchestrator import audit_from_manifest
    return audit_from_manifest(os.path.join(EXAMPLES, "genai_invest_stand.manifest.json"))


@pytest.fixture()
def write_json(tmp_path):
    def _w(name, obj):
        p = tmp_path / name
        p.write_text(json.dumps(obj, ensure_ascii=False, indent=1), encoding="utf-8")
        return str(p)
    return _w
