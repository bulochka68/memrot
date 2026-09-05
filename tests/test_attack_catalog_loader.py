import os

import pytest

from mcp_attack.catalog.loader import discover_catalog_files, load_catalog
from mcp_attack.catalog.schema import validate_catalog_file, validate_variant_dict

CATALOG_ROOT = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                            "mcp_attack", "catalog", "prompts")

FOLDERS = ["mem02_global_policy_poisoning", "mem01_03_cross_session_semantic_poisoning",
          "auth_tool_direct_bac_injection", "framing_diversity", "benign_control"]


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
    variants = load_catalog([os.path.join(CATALOG_ROOT, "benign_control")])
    assert all(v.rule_ids == [] for v in variants)


def test_discover_catalog_files_expands_directory():
    files = discover_catalog_files([os.path.join(CATALOG_ROOT, "mem02_global_policy_poisoning")])
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


def test_validate_variant_dict_single_turn_must_not_carry_inject_turns():
    errors = validate_variant_dict({
        "id": "x", "title": "x", "framing": "explicit_rule", "payload": "access_control_adjacent",
        "layer": "none", "propagation": "single-turn", "probe": "p",
        "inject_turns": ["should not be here"], "rule_ids": ["AUTH-02"],
    })
    assert any("single-turn" in e for e in errors)
