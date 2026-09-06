import os

from mcp_attack.audit_bridge import filter_variants_by_audit, load_audit_rule_ids
from mcp_attack.catalog.loader import load_catalog

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
STAND_AUDIT = os.path.join(ROOT, "examples", "genai_invest_stand.audit.json")
CATALOG_ROOT = os.path.join(ROOT, "mcp_attack", "catalog", "prompts")
ALL_CATALOG_PATHS = [os.path.join(CATALOG_ROOT, "domain", "invest_bank", f) for f in
                     ["mem02_global_policy_poisoning", "mem01_03_cross_session_semantic_poisoning",
                      "auth_tool_direct_bac_injection", "framing_diversity", "benign_control"]]


def test_load_audit_rule_ids_against_real_stand_report():
    info = load_audit_rule_ids(STAND_AUDIT)
    assert "MEM-02" in info["finding_rule_ids"]
    assert "MEM-02" in info["fail_rule_ids"]
    assert "MEM-02" in info["attackable_rule_ids"]


def test_filter_variants_by_audit_keeps_only_matched_rule_ids():
    variants = load_catalog(ALL_CATALOG_PATHS)
    filtered, limitations = filter_variants_by_audit(variants, STAND_AUDIT, mode="filter")
    assert len(filtered) < len(variants)
    assert all(set(v.rule_ids) & load_audit_rule_ids(STAND_AUDIT)["attackable_rule_ids"] for v in filtered)


def test_filter_variants_by_audit_prioritize_keeps_all_but_reorders():
    variants = load_catalog(ALL_CATALOG_PATHS)
    prioritized, _ = filter_variants_by_audit(variants, STAND_AUDIT, mode="prioritize")
    assert len(prioritized) == len(variants)


def test_filter_variants_by_audit_prefers_fail_control_results(write_json):
    from mcp_attack.models import AttackVariant
    variants = [
        AttackVariant(id="fail-hit", title="t", framing="none", payload="none", layer="none",
                      propagation="single-turn", probe="p", rule_ids=["MEM-02"]),
        AttackVariant(id="pass-only", title="t", framing="none", payload="none", layer="none",
                      propagation="single-turn", probe="p", rule_ids=["MEM-05"]),
    ]
    audit_path = write_json("audit.json", {
        "findings": [{"rule_id": "MEM-02"}, {"rule_id": "MEM-05"}],
        "control_results": [
            {"rule_id": "MEM-02", "control_outcome": "FAIL"},
            {"rule_id": "MEM-05", "control_outcome": "PASS"},
        ],
    })
    filtered, _ = filter_variants_by_audit(variants, audit_path, mode="filter")
    assert [v.id for v in filtered] == ["fail-hit"]


def test_empty_audit_findings_falls_back_to_full_catalog(write_json):
    variants = load_catalog(ALL_CATALOG_PATHS)
    empty_audit_path = write_json("empty_audit.json", {"findings": [], "downstream": {}})
    filtered, limitations = filter_variants_by_audit(variants, empty_audit_path, mode="filter")
    assert len(filtered) == len(variants)
    assert limitations
