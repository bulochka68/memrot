"""The shared audit-domain taxonomy (mcp_attack.audit_domains) that
redteam/attack_taxonomy.py re-exports, so the two no longer drift as
independent lists."""
from mcp_attack.audit_domains import (AUDIT_DOMAIN_CATEGORIES, CATEGORIES, DOMAIN_TO_OWASP_AMG,
                                      categories_for, known_slugs, title)
from mcp_attack.taxonomy import OWASP_AMG_CATEGORY_SLUGS


def test_expected_domain_slugs_present():
    assert set(known_slugs()) == {
        "memory-poisoning", "tool-poisoning", "idor-bac", "token-validation", "delegation",
        "exfiltration", "memory-hygiene", "infrastructure", "inventory",
    }


def test_categories_backward_compatible_shape_is_title_and_ruleid_set():
    # redteam CLIs unpack ``t, ids = CATEGORIES[slug]`` -- keep that shape.
    for slug, (t, ids) in CATEGORIES.items():
        assert isinstance(t, str) and t
        assert isinstance(ids, set)
        assert ids == set(AUDIT_DOMAIN_CATEGORIES[slug].rule_ids)


def test_categories_for_returns_domain_slugs_for_a_rule_id():
    assert categories_for("MEM-02") == ["memory-poisoning"]
    assert categories_for("TOOL-04") == ["tool-poisoning"]
    assert categories_for("NOT-A-RULE") == []


def test_title_falls_back_to_slug_for_unknown():
    assert title("memory-poisoning") == AUDIT_DOMAIN_CATEGORIES["memory-poisoning"].title
    assert title("nonsense") == "nonsense"


def test_domain_to_owasp_correspondence_only_maps_to_real_taxonomy_slugs():
    assert set(DOMAIN_TO_OWASP_AMG.values()) <= set(OWASP_AMG_CATEGORY_SLUGS)
    assert DOMAIN_TO_OWASP_AMG["memory-poisoning"] == "memory_prompt_injection"
    assert DOMAIN_TO_OWASP_AMG["tool-poisoning"] == "tool_output_instruction_injection"
    # auth/infra/inventory domains have no OWASP AMG memory/tool-poisoning analogue
    assert "idor-bac" not in DOMAIN_TO_OWASP_AMG


def test_redteam_shim_reexports_the_same_objects():
    import redteam.attack_taxonomy as shim
    assert shim.CATEGORIES is CATEGORIES
    assert shim.categories_for is categories_for
    assert shim.known_slugs is known_slugs
    assert shim.title is title
