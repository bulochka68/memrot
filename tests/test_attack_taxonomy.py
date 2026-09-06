import pytest

from memrot.taxonomy import (ATTACK_TECHNIQUE_CATEGORIES, ATTACK_TECHNIQUE_CATEGORY_SLUGS,
                                 OWASP_AMG_CATEGORIES, OWASP_AMG_CATEGORY_SLUGS, category,
                                 is_known_category, is_known_technique, technique_category)


def test_five_owasp_amg_memory_categories_plus_tool_channel_variant_are_present():
    # The 5 OWASP Agent Memory Guard categories (ASI06.1-5), plus a 6th slug
    # for the same instruction-injection mechanism delivered via a tool
    # result rather than a chat turn.
    assert len(OWASP_AMG_CATEGORY_SLUGS) == 6
    assert "memory_prompt_injection" in OWASP_AMG_CATEGORY_SLUGS
    assert "sensitive_data_leakage" in OWASP_AMG_CATEGORY_SLUGS
    assert "protected_key_tampering" in OWASP_AMG_CATEGORY_SLUGS
    assert "memory_integrity_violation" in OWASP_AMG_CATEGORY_SLUGS
    assert "bulk_injection_anomaly" in OWASP_AMG_CATEGORY_SLUGS
    assert "tool_output_instruction_injection" in OWASP_AMG_CATEGORY_SLUGS


def test_every_category_has_a_title_and_owasp_amg_id():
    for slug, cat in OWASP_AMG_CATEGORIES.items():
        assert cat.slug == slug
        assert cat.title
        assert cat.owasp_amg_id.startswith("ASI06.")
        assert cat.description


def test_category_lookup_raises_on_unknown_slug():
    with pytest.raises(KeyError):
        category("not_a_real_category")


def test_is_known_category():
    assert is_known_category("memory_prompt_injection") is True
    assert is_known_category("nonsense") is False


def test_memory_prompt_injection_cross_references_atlas_t0051():
    assert "AML.T0051" in category("memory_prompt_injection").atlas_technique_ids


def test_technique_category_registry_has_the_required_slugs():
    required = {
        "direct_instruction_override", "authority_impersonation", "obfuscation_encoding",
        "payload_splitting", "many_shot", "refusal_suppression", "roleplay_persona",
        "low_resource_language", "tool_result_injection", "context_ignore",
    }
    assert required <= set(ATTACK_TECHNIQUE_CATEGORY_SLUGS)
    for slug, cat in ATTACK_TECHNIQUE_CATEGORIES.items():
        assert cat.slug == slug
        assert cat.title
        assert cat.owasp_llm_id
        assert cat.description


def test_technique_category_lookup_mirrors_amg_helpers():
    assert is_known_technique("obfuscation_encoding") is True
    assert is_known_technique("not-a-slug") is False
    with pytest.raises(KeyError):
        technique_category("not-a-slug")
    assert technique_category("many_shot").slug == "many_shot"


def test_default_catalog_memory_variants_all_carry_owasp_amg_category():
    import os
    from memrot.catalog.loader import load_catalog
    root = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                        "memrot", "catalog", "prompts")
    variants = load_catalog([root])
    missing = [v.id for v in variants
               if v.threat_model == "memory_poisoning"
               and not (v.framing == "none" and v.payload == "none")
               and not v.owasp_amg_category]
    assert missing == []
