import os
import re

from mcp_attack.catalog.loader import load_catalog
from mcp_attack.catalog.schema import validate_catalog_file
from mcp_attack.cli import main

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
GENERIC = os.path.join(ROOT, "mcp_attack", "catalog", "prompts", "generic")
PROMPTS = os.path.join(ROOT, "mcp_attack", "catalog", "prompts")

DOMAIN_STOP = re.compile(
    r"портфел|клиент|\binvest|\bportfolio\b|\bbanks?\b|\bbanking\b|\bcus=|\bcus\b|\b100[1-5]\b",
    re.IGNORECASE,
)


def test_validate_catalog_strict_taxonomy_is_clean():
    assert main(["validate-catalog", PROMPTS, "--strict-taxonomy"]) == 0


def test_neutral_pool_has_no_domain_words():
    variants = load_catalog([GENERIC])
    assert variants
    for v in variants:
        haystack = " ".join([v.title, v.probe, v.trigger_message] + v.inject_turns)
        if v.tool_stage:
            haystack += " " + " ".join(v.tool_stage.values())
        assert DOMAIN_STOP.search(haystack) is None, (v.id, haystack)


def test_new_generic_technique_pools_are_present_and_tagged():
    expected = {
        "generic_obfuscation_encoding": "obfuscation_encoding",
        "generic_payload_splitting": "payload_splitting",
        "generic_many_shot": "many_shot",
        "generic_refusal_suppression": "refusal_suppression",
        "generic_context_ignore": "context_ignore",
        "generic_low_resource_language": "low_resource_language",
    }
    variants = load_catalog([GENERIC])
    folders = {name for name in os.listdir(GENERIC) if os.path.isdir(os.path.join(GENERIC, name))}
    assert expected.keys() <= folders
    by_tech = {slug: [v for v in variants if v.technique_category == slug] for slug in expected.values()}
    for slug, group in by_tech.items():
        assert group, slug
        for v in group:
            assert v.technique_category
            assert v.taxonomy or v.owasp_amg_category


def test_strict_taxonomy_rejects_memory_variant_without_amg(tmp_path):
    path = tmp_path / "catalog.json"
    path.write_text(
        '{"domain":"neutral","variants":[{"id":"x","title":"x","framing":"explicit_rule",'
        '"payload":"formatting_marker","layer":"policy_global","propagation":"cross-user",'
        '"probe":"p","canary_template":"C-{canary}","inject_turns":["hi {canary}"],'
        '"rule_ids":[],"taxonomy":["AML.T0051"]}]}',
        encoding="utf-8",
    )
    errors = validate_catalog_file(str(path), require_taxonomy=True)
    assert any("memory_poisoning variant must carry owasp_amg_category" in e for e in errors)
