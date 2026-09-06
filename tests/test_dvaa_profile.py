"""Третья топология: Damn Vulnerable AI Agent (Node.js, MCP поверх HTTP).

Проверяет, что те же правила и тот же формат finding работают на системе,
написанной не на Python и говорящей по MCP без ``initialize``: привязка живёт
в profiles/dvaa.json, движок не меняется. Прогон offline — читает снимок
инвентаря, исходники стенда из stand/, политику и compose; ничего не запускает.
"""
import json
import os

import pytest

from mcp_audit.models import ControlOutcome
from mcp_audit.orchestrator import audit_from_manifest
from mcp_audit.reporting import emit_json
from mcp_audit.validation import validate_document

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
MANIFEST = os.path.join(ROOT, "examples", "dvaa.manifest.json")
STAND = os.path.join(ROOT, "stand", "src", "index.js")

pytestmark = pytest.mark.skipif(not os.path.isfile(STAND),
                                reason="исходники стенда (stand/) не выложены в этом чекауте")


@pytest.fixture(scope="module")
def dvaa_doc():
    return audit_from_manifest(MANIFEST)


def test_js_sources_are_verified_by_pattern_not_by_ast(dvaa_doc):
    """symbol в профиле не задан: поток подтверждается регулярным выражением по файлу."""
    flows = {f["id"]: f for f in dvaa_doc.source_facts.get("flows") or []}
    assert flows, "профиль не дал ни одного потока"
    unknown = [i for i, f in flows.items() if f.get("status") == "unknown"]
    assert unknown == [], f"источник не найден для потоков: {unknown}"
    a2a = flows["F-identity-a2a"]
    assert a2a["status"] == "static_supported"
    assert a2a["evidence"]["locator"]["path"] == "src/index.js"
    # ast-разбора для .js нет, поэтому локатор — файл целиком, а не символ
    assert a2a["evidence"]["locator"]["symbol"] is None


def test_core_defects_of_the_stand_are_found(dvaa_doc):
    outcomes = {r.rule_id: r.control_outcome for r in dvaa_doc.control_results}
    for rule in ("MEM-01", "MEM-02", "MEM-03", "MEM-04", "AUTH-01", "AUTH-02", "AUTH-05", "EGRESS-01"):
        assert outcomes[rule] == ControlOutcome.FAIL, f"{rule}: ожидался FAIL, получено {outcomes[rule]}"
    codes = {f.code for f in dvaa_doc.findings}
    assert {"IDENTITY_FROM_UNTRUSTED_FIELD", "RESOURCE_AUTHORIZATION_MISSING",
            "UNBOUNDED_DELEGATION", "MEMORY_ISOLATION_MISSING"} <= codes


def test_inventory_comes_from_a_snapshot_not_from_a_handshake(dvaa_doc):
    """У стенда нет initialize, поэтому live-хендшейка быть не должно — только снимок."""
    toolbot = dvaa_doc.server("toolbot")
    assert toolbot is not None
    assert toolbot.handshake.performed is False
    assert toolbot.handshake.source == "snapshot"
    assert {t.name for t in toolbot.tools} == {"read_file", "write_file", "execute", "fetch_url"}
    assert dvaa_doc.control_result("INV-02").control_outcome == ControlOutcome.PASS


def test_report_validates_against_the_schema(dvaa_doc):
    assert validate_document(json.loads(emit_json(dvaa_doc))) == []
