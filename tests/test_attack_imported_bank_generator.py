import json
import os

import pytest

from mcp_attack.catalog.generator import ImportedBankGenerator, build_generator

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
GARAK_DAN_DIR = os.path.join(ROOT, "mcp_attack", "catalog", "imported", "garak_dan")
TRUSTAIRLAB_SAMPLE = os.path.join(ROOT, "mcp_attack", "catalog", "imported", "trustairlab_jailbreak", "sample.json")


def test_unknown_bank_rejected():
    with pytest.raises(ValueError, match="unknown bank"):
        ImportedBankGenerator("not_a_real_bank", "/some/path")


def test_garak_dan_generates_one_variant_per_prompt_across_all_14_files():
    variants = ImportedBankGenerator("garak_dan", GARAK_DAN_DIR).generate()
    n_prompts = 0
    for name in os.listdir(GARAK_DAN_DIR):
        if name.endswith(".json"):
            n_prompts += len(json.load(open(os.path.join(GARAK_DAN_DIR, name), encoding="utf-8")))
    assert len(variants) == n_prompts
    ids = [v.id for v in variants]
    assert len(ids) == len(set(ids))


def test_garak_dan_variants_are_tagged_llm_jailbreak_susceptibility_not_memory_poisoning():
    variants = ImportedBankGenerator("garak_dan", GARAK_DAN_DIR).generate()
    assert all(v.threat_model == "llm_jailbreak_susceptibility" for v in variants)
    assert all(v.owasp_amg_category == "" for v in variants)
    assert all(v.rule_ids == [] for v in variants)
    assert all(v.source == "imported:garak_dan" for v in variants)


def test_garak_dan_probe_is_instrumented_with_a_literal_compliance_marker():
    variants = ImportedBankGenerator("garak_dan", GARAK_DAN_DIR).generate()
    for v in variants:
        assert v.canary_template
        assert v.canary_template in v.probe   # the exact marker string appears verbatim in the probe
        assert v.propagation == "single-turn"
        assert v.inject_turns == []


def test_garak_dan_canary_templates_are_unique_per_variant():
    variants = ImportedBankGenerator("garak_dan", GARAK_DAN_DIR).generate()
    markers = [v.canary_template for v in variants]
    assert len(markers) == len(set(markers))


def test_garak_dan_sample_size_subsamples_deterministically():
    a = ImportedBankGenerator("garak_dan", GARAK_DAN_DIR, sample_size=5, seed=42).generate()
    b = ImportedBankGenerator("garak_dan", GARAK_DAN_DIR, sample_size=5, seed=42).generate()
    assert len(a) == 5
    assert [v.id for v in a] == [v.id for v in b]


def test_trustairlab_generates_all_144_curated_prompts_by_default():
    variants = ImportedBankGenerator("trustairlab_jailbreak", TRUSTAIRLAB_SAMPLE).generate()
    raw = json.load(open(TRUSTAIRLAB_SAMPLE, encoding="utf-8"))
    assert len(variants) == len(raw)
    ids = [v.id for v in variants]
    assert len(ids) == len(set(ids))
    assert all(v.threat_model == "llm_jailbreak_susceptibility" for v in variants)
    assert all(v.source == "imported:trustairlab_jailbreak" for v in variants)


def test_trustairlab_sample_size_subsamples_deterministically():
    a = ImportedBankGenerator("trustairlab_jailbreak", TRUSTAIRLAB_SAMPLE, sample_size=10, seed=7).generate()
    b = ImportedBankGenerator("trustairlab_jailbreak", TRUSTAIRLAB_SAMPLE, sample_size=10, seed=7).generate()
    assert len(a) == 10
    assert [v.id for v in a] == [v.id for v in b]


def test_ids_never_double_prefixed():
    variants = ImportedBankGenerator("trustairlab_jailbreak", TRUSTAIRLAB_SAMPLE, sample_size=20, seed=1).generate()
    for v in variants:
        assert not v.id.startswith("trustairlab-trustairlab-")


def test_build_generator_registers_imported_bank():
    gen = build_generator("imported_bank", bank="garak_dan", source_path=GARAK_DAN_DIR)
    assert isinstance(gen, ImportedBankGenerator)
    assert len(gen.generate()) == 14 or len(gen.generate()) > 14   # at least one prompt per of the 14 files
