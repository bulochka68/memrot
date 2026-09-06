import os

import pytest

from memrot.catalog.loader import discover_catalog_files, load_catalog
from memrot.catalog.schema import validate_catalog_file, validate_variant_dict

CATALOG_ROOT = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                            "memrot", "catalog", "prompts")

FOLDERS = [
    "domain/invest_bank/mem02_global_policy_poisoning",
    "domain/invest_bank/mem01_03_cross_session_semantic_poisoning",
    "domain/invest_bank/auth_tool_direct_bac_injection",
    "domain/invest_bank/framing_diversity",
    "domain/invest_bank/benign_control",
    "generic/generic_memory_prompt_injection",
    "generic/generic_sensitive_data_leakage",
    "generic/generic_protected_key_tampering",
    "generic/generic_memory_integrity_violation",
    "generic/generic_bulk_injection_anomaly",
    "generic/generic_tool_output_instruction_injection",
]

GENERIC_FOLDER_TO_CATEGORY = {
    "generic/generic_memory_prompt_injection": "memory_prompt_injection",
    "generic/generic_sensitive_data_leakage": "sensitive_data_leakage",
    "generic/generic_protected_key_tampering": "protected_key_tampering",
    "generic/generic_memory_integrity_violation": "memory_integrity_violation",
    "generic/generic_bulk_injection_anomaly": "bulk_injection_anomaly",
    "generic/generic_tool_output_instruction_injection": "tool_output_instruction_injection",
}


@pytest.mark.parametrize("folder", FOLDERS)
def test_shipped_catalog_folder_is_valid(folder):
    path = os.path.join(CATALOG_ROOT, folder, "catalog.json")
    errors = validate_catalog_file(path)
    assert errors == []


def test_load_catalog_across_all_shipped_folders_has_unique_ids():
    paths = [os.path.join(CATALOG_ROOT, f) for f in FOLDERS]
    variants = load_catalog(paths)
    ids = [v.id for v in variants]
    assert len(ids) == len(set(ids))
    assert len(variants) >= 20   # breadth-over-volume target from the plan


def test_benign_control_variants_carry_no_rule_ids():
    variants = load_catalog([os.path.join(CATALOG_ROOT, "domain", "invest_bank", "benign_control")])
    assert all(v.rule_ids == [] for v in variants)


def test_discover_catalog_files_expands_directory():
    files = discover_catalog_files([os.path.join(CATALOG_ROOT, "domain", "invest_bank", "mem02_global_policy_poisoning")])
    assert len(files) == 1
    assert files[0].endswith("catalog.json")


def test_discover_catalog_files_missing_path_raises():
    with pytest.raises(FileNotFoundError):
        discover_catalog_files(["/no/such/path"])


def test_validate_variant_dict_flags_bad_enum():
    errors = validate_variant_dict({
        "id": "x", "title": "x", "framing": "not-a-real-value", "payload": "formatting_marker",
        "layer": "policy_global", "propagation": "cross-user", "probe": "p",
        "canary_template": "C-{canary}", "inject_turns": ["hi {canary}"], "rule_ids": ["MEM-02"],
    })
    assert any("framing" in e for e in errors)


def test_validate_variant_dict_requires_canary_for_cross_user():
    errors = validate_variant_dict({
        "id": "x", "title": "x", "framing": "explicit_rule", "payload": "formatting_marker",
        "layer": "policy_global", "propagation": "cross-user", "probe": "p",
        "canary_template": "", "inject_turns": ["hi"], "rule_ids": ["MEM-02"],
    })
    assert any("canary_template" in e for e in errors)


@pytest.mark.parametrize("folder,category", sorted(GENERIC_FOLDER_TO_CATEGORY.items()))
def test_generic_folder_variants_are_tagged_with_their_owasp_amg_category(folder, category):
    variants = load_catalog([os.path.join(CATALOG_ROOT, folder)])
    assert variants   # non-empty pool
    assert all(v.owasp_amg_category == category for v in variants)


def test_generic_folders_carry_no_audit_specific_rule_ids():
    """The whole point of the generic_* pool is to be runnable against any
    agent, not just the bank stand -- so it must not depend on mcp_audit's
    stand-specific rule catalogue."""
    paths = [os.path.join(CATALOG_ROOT, f) for f in GENERIC_FOLDER_TO_CATEGORY]
    variants = load_catalog(paths)
    assert all(v.rule_ids == [] for v in variants)


def test_generic_folders_avoid_bank_stand_specific_wording():
    paths = [os.path.join(CATALOG_ROOT, f) for f in GENERIC_FOLDER_TO_CATEGORY]
    variants = load_catalog(paths)
    banned = ("портфел", "cus=", "банк", "клиент")   # bank/stand-specific tokens used by mem02/bac catalogs
    for v in variants:
        haystack = " ".join([v.probe] + v.inject_turns).lower()
        assert not any(b in haystack for b in banned), (v.id, haystack)


def test_owasp_amg_category_unknown_slug_is_rejected():
    errors = validate_variant_dict({
        "id": "x", "title": "x", "framing": "explicit_rule", "payload": "none",
        "layer": "none", "propagation": "single-turn", "probe": "p",
        "rule_ids": [], "owasp_amg_category": "not_a_real_category",
    })
    assert any("owasp_amg_category" in e for e in errors)


def test_validate_variant_dict_single_turn_must_not_carry_inject_turns():
    errors = validate_variant_dict({
        "id": "x", "title": "x", "framing": "explicit_rule", "payload": "access_control_adjacent",
        "layer": "none", "propagation": "single-turn", "probe": "p",
        "inject_turns": ["should not be here"], "rule_ids": ["AUTH-02"],
    })
    assert any("single-turn" in e for e in errors)
