import os

from mcp_attack.audit_plan import (RULE_ID_TO_OWASP_AMG_CATEGORY, SEV_RANK, extract_ranked_findings,
                                   select_variants_by_audit)
from mcp_attack.catalog.loader import load_catalog
from mcp_attack.models import AttackVariant

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
REAL_AUDIT = os.path.join(ROOT, "examples", "genai_invest_stand.audit.json")
CATALOG_ROOT = os.path.join(ROOT, "mcp_attack", "catalog", "prompts")


def _finding(rule_id, severity=None, effective_severity=None):
    return {"rule_id": rule_id, "severity": severity, "effective_severity": effective_severity}


def _doc(findings, control_results):
    return {"findings": findings, "control_results": control_results}


def test_sev_rank_orders_critical_first():
    assert SEV_RANK["CRITICAL"] < SEV_RANK["HIGH"] < SEV_RANK["MEDIUM"] < SEV_RANK["LOW"] < SEV_RANK[None]


def test_extract_ranked_findings_uses_effective_severity_over_severity():
    doc = _doc(
        [_finding("MEM-02", severity=None, effective_severity="CRITICAL")],
        [{"rule_id": "MEM-02", "control_outcome": "FAIL"}],
    )
    ranked = extract_ranked_findings(doc)
    assert len(ranked) == 1
    assert ranked[0].severity == "CRITICAL"


def test_extract_ranked_findings_excludes_non_fail_by_default():
    doc = _doc(
        [_finding("MEM-02", severity="CRITICAL"), _finding("MEM-03", severity="HIGH")],
        [{"rule_id": "MEM-02", "control_outcome": "FAIL"}, {"rule_id": "MEM-03", "control_outcome": "PASS"}],
    )
    ranked = extract_ranked_findings(doc)
    assert [rf.rule_id for rf in ranked] == ["MEM-02"]


def test_extract_ranked_findings_sorts_by_severity_then_rule_id():
    doc = _doc(
        [_finding("MEM-05", severity="LOW"), _finding("MEM-02", severity="CRITICAL"),
         _finding("TOOL-04", severity="HIGH")],
        [{"rule_id": r, "control_outcome": "FAIL"} for r in ("MEM-05", "MEM-02", "TOOL-04")],
    )
    ranked = extract_ranked_findings(doc)
    assert [rf.rule_id for rf in ranked] == ["MEM-02", "TOOL-04", "MEM-05"]


def test_extract_ranked_findings_min_severity_filters_below_threshold():
    doc = _doc(
        [_finding("MEM-02", severity="CRITICAL"), _finding("MEM-05", severity="LOW")],
        [{"rule_id": r, "control_outcome": "FAIL"} for r in ("MEM-02", "MEM-05")],
    )
    ranked = extract_ranked_findings(doc, min_severity="HIGH")
    assert [rf.rule_id for rf in ranked] == ["MEM-02"]


def test_extract_ranked_findings_bridges_known_rule_ids_to_owasp_category():
    doc = _doc([_finding("MEM-02", severity="HIGH")], [{"rule_id": "MEM-02", "control_outcome": "FAIL"}])
    ranked = extract_ranked_findings(doc)
    assert ranked[0].owasp_amg_category == "memory_prompt_injection"


def test_extract_ranked_findings_leaves_unmapped_rule_ids_honestly_blank():
    doc = _doc([_finding("AUTH-02", severity="CRITICAL")], [{"rule_id": "AUTH-02", "control_outcome": "FAIL"}])
    ranked = extract_ranked_findings(doc)
    assert ranked[0].owasp_amg_category == ""


def test_bridge_table_only_maps_to_real_taxonomy_slugs():
    from mcp_attack.taxonomy import OWASP_AMG_CATEGORY_SLUGS
    assert set(RULE_ID_TO_OWASP_AMG_CATEGORY.values()) <= set(OWASP_AMG_CATEGORY_SLUGS)


def _variant(id_, owasp_amg_category="", rule_ids=None) -> AttackVariant:
    return AttackVariant(id=id_, title=id_, framing="none", payload="none", layer="none",
                         propagation="single-turn", probe="p", owasp_amg_category=owasp_amg_category,
                         rule_ids=rule_ids or [])


def test_select_variants_by_audit_never_drops_a_variant(write_json):
    doc = _doc([_finding("MEM-02", severity="CRITICAL")], [{"rule_id": "MEM-02", "control_outcome": "FAIL"}])
    audit_path = write_json("audit.json", doc)
    variants = [_variant("a", owasp_amg_category="memory_prompt_injection"), _variant("b"), _variant("c")]
    ordered, _ = select_variants_by_audit(variants, audit_path)
    assert {v.id for v in ordered} == {"a", "b", "c"}
    assert len(ordered) == 3


def test_select_variants_by_audit_orders_matched_category_first(write_json):
    doc = _doc([_finding("MEM-02", severity="CRITICAL")], [{"rule_id": "MEM-02", "control_outcome": "FAIL"}])
    audit_path = write_json("audit.json", doc)
    variants = [_variant("unrelated"), _variant("matched", owasp_amg_category="memory_prompt_injection")]
    ordered, _ = select_variants_by_audit(variants, audit_path)
    assert ordered[0].id == "matched"


def test_select_variants_by_audit_falls_back_to_rule_id_for_unmapped_categories(write_json):
    doc = _doc([_finding("AUTH-02", severity="CRITICAL")], [{"rule_id": "AUTH-02", "control_outcome": "FAIL"}])
    audit_path = write_json("audit.json", doc)
    variants = [_variant("unrelated"), _variant("matched_by_rule_id", rule_ids=["AUTH-02"])]
    ordered, limitations = select_variants_by_audit(variants, audit_path)
    assert ordered[0].id == "matched_by_rule_id"
    assert any("AUTH-02" in l for l in limitations)


def test_select_variants_by_audit_top_n_truncates_and_keeps_order(write_json):
    doc = _doc([_finding("MEM-02", severity="CRITICAL")], [{"rule_id": "MEM-02", "control_outcome": "FAIL"}])
    audit_path = write_json("audit.json", doc)
    variants = [
        _variant("z-unrelated"),
        _variant("a-matched", owasp_amg_category="memory_prompt_injection"),
        _variant("b-matched", owasp_amg_category="memory_prompt_injection"),
        _variant("c-unrelated"),
    ]
    ordered, _ = select_variants_by_audit(variants, audit_path, top_n=2)
    assert [v.id for v in ordered] == ["a-matched", "b-matched"]


def test_real_audit_ranks_bac_variants_ahead_of_memory_only_variants():
    variants = load_catalog([CATALOG_ROOT])
    ordered, limitations = select_variants_by_audit(variants, REAL_AUDIT)
    bac_ids = {v.id for v in variants if "AUTH-02" in v.rule_ids}
    mem_ids = {v.id for v in variants if "MEM-02" in v.rule_ids and "AUTH-02" not in v.rule_ids}
    assert bac_ids and mem_ids
    first_bac = min(i for i, v in enumerate(ordered) if v.id in bac_ids)
    first_mem = min(i for i, v in enumerate(ordered) if v.id in mem_ids)
    assert first_bac < first_mem
    assert any("AUTH-02" in l or "unmapped" in l.lower() or "no owasp_amg_category" in l for l in limitations)


def test_select_variants_by_audit_higher_severity_wins_over_lower(write_json):
    doc = _doc(
        [_finding("MEM-02", severity="LOW"), _finding("MEM-04", severity="CRITICAL")],
        [{"rule_id": r, "control_outcome": "FAIL"} for r in ("MEM-02", "MEM-04")],
    )
    audit_path = write_json("audit.json", doc)
    # both bridge to memory_prompt_injection -- best (CRITICAL) rank should win for that category
    variants = [_variant("x", owasp_amg_category="memory_prompt_injection"), _variant("y")]
    ordered, _ = select_variants_by_audit(variants, audit_path)
    assert ordered[0].id == "x"


def test_select_variants_by_audit_no_fail_findings_returns_unchanged_order(write_json):
    doc = _doc([_finding("MEM-02", severity="CRITICAL")], [{"rule_id": "MEM-02", "control_outcome": "PASS"}])
    audit_path = write_json("audit.json", doc)
    variants = [_variant("b"), _variant("a")]
    ordered, limitations = select_variants_by_audit(variants, audit_path)
    assert [v.id for v in ordered] == ["b", "a"]
    assert limitations


def test_select_variants_by_audit_rejects_unknown_mode(write_json):
    doc = _doc([], [])
    audit_path = write_json("audit.json", doc)
    import pytest
    with pytest.raises(ValueError, match="mode='ranked'"):
        select_variants_by_audit([], audit_path, mode="filter")


# --------------------------------------------------------------------------- #
# Real fixture: examples/genai_invest_stand.audit.json against the shipped catalog
# --------------------------------------------------------------------------- #

def test_real_audit_fixture_ranks_the_full_shipped_catalog():
    variants = load_catalog([CATALOG_ROOT])
    ordered, limitations = select_variants_by_audit(variants, REAL_AUDIT)
    assert {v.id for v in ordered} == {v.id for v in variants}   # nothing dropped
    assert len(ordered) == len(variants)
    # the real fixture has a CRITICAL MEM-02 finding -- MEM-02-tagged variants
    # should sort ahead of anything with no matching category or rule_id at all
    mem02_ids = {v.id for v in variants if "MEM-02" in v.rule_ids or v.owasp_amg_category == "memory_prompt_injection"}
    untagged_ids = {v.id for v in variants if not v.rule_ids and not v.owasp_amg_category}
    if mem02_ids and untagged_ids:
        first_mem02_rank = min(i for i, v in enumerate(ordered) if v.id in mem02_ids)
        first_untagged_rank = min(i for i, v in enumerate(ordered) if v.id in untagged_ids)
        assert first_mem02_rank < first_untagged_rank
