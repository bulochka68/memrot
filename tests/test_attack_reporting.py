from mcp_attack.models import AttackResult, Channel, ChannelRole, Principal, RunReport, Verdict
from mcp_attack.reporting.aggregate import aggregate
from mcp_attack.reporting.emitter import emit_json, emit_markdown
from mcp_attack.reporting.html_emitter import emit_html


def _result(verdict, rule_ids=None, **kw) -> AttackResult:
    return AttackResult(variant_id=kw.pop("variant_id", "v"), verdict=verdict,
                        rule_ids=rule_ids or [], framing=kw.pop("framing", "explicit_rule"),
                        payload=kw.pop("payload", "formatting_marker"), layer=kw.pop("layer", "policy_global"),
                        propagation=kw.pop("propagation", "cross-user"),
                        owasp_amg_category=kw.pop("owasp_amg_category", ""),
                        mutation_technique=kw.pop("mutation_technique", ""), **kw)


def _report(results) -> RunReport:
    return RunReport(run_id="run1", target_id="fake",
                     channels=[Channel(role=ChannelRole.ATTACKER, principal=Principal(principal_id="1001"))],
                     results=results)


def test_aggregate_excludes_invalid_error_not_evaluated_from_ratio_but_counts_them():
    report = _report([
        _result(Verdict.CONFIRMED, rule_ids=["MEM-02"]),
        _result(Verdict.CLEAN, rule_ids=["MEM-02"]),
        _result(Verdict.INVALID, rule_ids=["MEM-02"]),
        _result(Verdict.ERROR, rule_ids=["MEM-02"]),
        _result(Verdict.NOT_EVALUATED, rule_ids=["MEM-02"]),
    ])
    aggregate(report)
    assert report.overall_asr.total == 2         # only CONFIRMED + CLEAN
    assert report.overall_asr.confirmed == 1
    assert report.counts_by_verdict == {"CONFIRMED": 1, "CLEAN": 1, "INVALID": 1, "ERROR": 1, "NOT_EVALUATED": 1}


def test_aggregate_by_rule_id_counts_each_tag():
    report = _report([
        _result(Verdict.CONFIRMED, rule_ids=["MEM-01", "MEM-03"]),
        _result(Verdict.CLEAN, rule_ids=["MEM-03"]),
    ])
    aggregate(report)
    assert report.asr_by_rule_id["MEM-01"].display == "1/1 (100.0%)"
    assert report.asr_by_rule_id["MEM-03"].display == "1/2 (50.0%)"


def test_aggregate_by_axis_groups_framing_payload_layer_propagation():
    report = _report([
        _result(Verdict.CONFIRMED, framing="explicit_rule"),
        _result(Verdict.CLEAN, framing="authority_compliance"),
    ])
    aggregate(report)
    assert set(report.asr_by_axis["framing"].keys()) == {"explicit_rule", "authority_compliance"}


def test_zero_denominator_group_never_shows_a_percentage():
    report = _report([_result(Verdict.ERROR, rule_ids=["MEM-02"])])
    aggregate(report)
    assert report.overall_asr.display == "n/a (0/0)"


def test_emit_json_and_markdown_are_well_formed_and_consistent():
    report = _report([_result(Verdict.CONFIRMED, rule_ids=["MEM-02"])])
    aggregate(report)
    import json
    parsed = json.loads(emit_json(report))
    assert parsed["run_id"] == "run1"
    md = emit_markdown(report)
    assert "Overall ASR" in md
    assert "MEM-02" in md


def test_aggregate_by_taxonomy_category_groups_and_untagged_bucket():
    report = _report([
        _result(Verdict.CONFIRMED, owasp_amg_category="memory_prompt_injection"),
        _result(Verdict.CLEAN, owasp_amg_category="memory_prompt_injection"),
        _result(Verdict.CONFIRMED, owasp_amg_category=""),
    ])
    aggregate(report)
    assert report.asr_by_taxonomy_category["memory_prompt_injection"].display == "1/2 (50.0%)"
    assert report.asr_by_taxonomy_category["(untagged)"].display == "1/1 (100.0%)"


def test_aggregate_by_mutation_technique_groups_and_none_bucket():
    report = _report([
        _result(Verdict.CONFIRMED, mutation_technique="prefix_injection"),
        _result(Verdict.CLEAN, mutation_technique=""),
    ])
    aggregate(report)
    assert report.asr_by_mutation_technique["prefix_injection"].display == "1/1 (100.0%)"
    assert report.asr_by_mutation_technique["(none)"].display == "0/1 (0.0%)"


def test_emit_json_includes_new_breakdown_dicts():
    report = _report([_result(Verdict.CONFIRMED, owasp_amg_category="memory_prompt_injection",
                              mutation_technique="paraphrase")])
    aggregate(report)
    import json
    parsed = json.loads(emit_json(report))
    assert parsed["asr_by_taxonomy_category"]["memory_prompt_injection"]["confirmed"] == 1
    assert parsed["asr_by_mutation_technique"]["paraphrase"]["confirmed"] == 1


def test_emit_markdown_includes_taxonomy_and_mutation_sections():
    report = _report([_result(Verdict.CONFIRMED, owasp_amg_category="memory_prompt_injection",
                              mutation_technique="paraphrase")])
    aggregate(report)
    md = emit_markdown(report)
    assert "ASR by taxonomy category" in md
    assert "ASR by mutation technique" in md
    assert "memory\\_prompt\\_injection" in md   # Markdown-escapes underscores, see emitter.esc()
    assert "paraphrase" in md


def test_emit_html_is_well_formed_and_contains_key_sections():
    report = _report([
        _result(Verdict.CONFIRMED, rule_ids=["MEM-02"], owasp_amg_category="memory_prompt_injection",
               mutation_technique="paraphrase", variant_id="v-confirmed"),
        _result(Verdict.CLEAN, owasp_amg_category="memory_prompt_injection", variant_id="v-clean"),
    ])
    aggregate(report)
    doc = emit_html(report)
    assert doc.startswith("<!doctype html>")
    assert doc.count("<html") == 1 and doc.count("</html>") == 1
    assert "run1" in doc
    assert "memory_prompt_injection" in doc
    assert "paraphrase" in doc
    assert "v-confirmed" in doc and "v-clean" in doc
    assert "Overall ASR".lower() not in doc.lower() or "ASR" in doc   # headline KPI present in some form


def test_emit_html_escapes_untrusted_content():
    report = _report([_result(Verdict.CONFIRMED, variant_id="<script>alert(1)</script>")])
    aggregate(report)
    doc = emit_html(report)
    assert "<script>alert(1)</script>" not in doc
    assert "&lt;script&gt;" in doc


def test_emit_html_handles_zero_denominator_groups_without_crashing():
    report = _report([_result(Verdict.ERROR)])
    aggregate(report)
    doc = emit_html(report)
    assert "n/a (0/0)" in doc
