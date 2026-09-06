"""Portability of the auditor: a new stand is data, not a patch of ``mcp_audit``.

Third topology (``tests/fixtures/registry_stand``): a foreign MCP server that
declares its tools in a module-level registry, keeps part of the catalogue in a
JSON file, speaks a domain vocabulary the engine has never seen and has a
TypeScript front-end.  Nothing in the package knows about it.

Covered:  extraction strategies (P0-1), explicit capability declarations (P0-2),
the profile linter (P0-3), the lexicon and server kinds as data (P1-4/P1-5),
adapter plugins (P2-6) and non-Python sources (P2-7) - plus the regression that
the existing stand is classified exactly as before.
"""
import json
import os

import pytest

from mcp_audit.adapters import AdapterBinding
from mcp_audit.adapters.registry import known_kinds, load_plugin, load_plugins
from mcp_audit.adapters.source_snapshot import SourceScanner, extract_facts
from mcp_audit.classification import classify_tool
from mcp_audit.classification.lexicon import LexiconError, base_lexicon, build_pattern, load_lexicon
from mcp_audit.cli import main as cli_main
from mcp_audit.manifest import Manifest
from mcp_audit.models import (AccessProfile, ControlOutcome, KnowledgeState, Operation, RunMode,
                              ToolDefinition, ToolRecord)
from mcp_audit.orchestrator import Orchestrator
from mcp_audit.reporting import emit_json
from mcp_audit.validation import lint_profile, validate_document

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
STAND = os.path.join(HERE, "fixtures", "registry_stand")
SRC = os.path.join(STAND, "src")
REGRESSION = os.path.join(HERE, "fixtures", "regression")


def _profile():
    with open(os.path.join(STAND, "profile.json"), encoding="utf-8") as fh:
        return json.load(fh)


def _tool(name, desc="", annotations=None, declared=None):
    return ToolRecord(server="vault", definition=ToolDefinition(name=name, description=desc,
                                                                annotations=annotations or {},
                                                                declared=declared or {}))


@pytest.fixture(scope="module")
def facts():
    return extract_facts(SRC, _profile()["source_facts"])


@pytest.fixture(scope="module")
def registry_doc():
    m = Manifest(target={"id": "registry-stand", "build_ref": "fixture-1", "environment": "fixture"},
                 access_profile=AccessProfile.WHITE_BOX, mode=RunMode.OFFLINE,
                 profile_ref=os.path.join(STAND, "profile.json"),
                 adapters=[AdapterBinding("mcp-config", "mcp_inventory",
                                          {"path": os.path.join(STAND, "vault.config.json"), "live": False}, base_dir=STAND),
                           AdapterBinding("source", "source_snapshot", {"root": SRC}, base_dir=STAND),
                           AdapterBinding("policy", "policy_snapshot", {"path": os.path.join(STAND, "policy.json")}, base_dir=STAND)],
                 base_dir=STAND)
    return Orchestrator(m).run()


# --------------------------------------------------------------------------- #
# P0-1  extraction strategies
# --------------------------------------------------------------------------- #

def test_registry_dict_declarations_are_read_without_a_decorator(facts):
    by_name = {d["name"]: d for d in facts["tool_declarations"] if d.get("name")}
    mine = by_name["vault_mine_note"]
    assert mine["status"] == "static_supported" and mine["strategy"] == "registry_dict"
    assert mine["description"].startswith("Mine a note")
    assert sorted(mine["input_schema"]["properties"]) == ["subject_id", "text"]
    assert mine["input_schema"]["required"] == ["subject_id", "text"]
    assert mine["symbol"] == "TOOLS['vault_mine_note']" and mine["lineno"] > 0
    assert mine["digest"].startswith("sha256:")


def test_computed_registry_entry_is_unknown_not_silently_skipped(facts):
    generated = [d for d in facts["tool_declarations"] if d.get("name") == "vault_generated"]
    assert len(generated) == 1, "a definition built at import time must still be listed"
    assert generated[0]["status"] == "unknown"
    assert "not a constant mapping" in generated[0]["reason"]


def test_list_literal_and_json_file_strategies(facts):
    by_strategy = {}
    for d in facts["tool_declarations"]:
        by_strategy.setdefault(d.get("strategy"), []).append(d)
    assert [d["name"] for d in by_strategy["list_literal"]] == ["vault_hallway_map"]
    exported = by_strategy["json_file"][0]
    assert exported["name"] == "vault_export_wing" and exported["status"] == "static_supported"
    assert exported["declared"] == {"operations": ["READ", "TRANSMIT"], "egress": True}
    assert exported["digest"].startswith("sha256:")     # the data file is pinned like a source file


def test_decorator_strategy_is_the_default_and_unchanged():
    scanner = SourceScanner(os.path.join(HERE, "fixtures", "rest_native_agent", "src"))
    decls = scanner.tool_declarations("app/tools.py")
    assert {d["name"] for d in decls} == {"search_docs", "send_summary"}
    assert all(d["strategy"] == "decorator" for d in decls)


def test_unknown_strategy_and_missing_symbol_say_why():
    scanner = SourceScanner(SRC)
    bad = scanner.tool_declarations("server.py", {"strategy": "telepathy"})
    assert bad[0]["status"] == "unknown" and "unknown extraction strategy" in bad[0]["reason"]
    missing = scanner.tool_declarations("server.py", {"strategy": "registry_dict", "symbol": "NOPE"})
    assert missing[0]["status"] == "unknown" and "not found" in missing[0]["reason"]


# --------------------------------------------------------------------------- #
# P2-7  languages without an AST
# --------------------------------------------------------------------------- #

def test_regex_only_verifies_a_fact_in_a_non_python_file(facts):
    flow = {f["id"]: f for f in facts["flows"]}["R-digest-transmit"]
    assert flow["status"] == "static_supported"
    locator = flow["evidence"]["locator"]
    assert locator["path"] == "ui/client.ts" and locator["symbol"] is None
    assert locator["strategy"] == "regex_only" and locator["lines"][0] == 1


def test_symbol_in_an_unsupported_language_names_the_language():
    spec = {"flows": [{"id": "R-ts", "path": "ui/client.ts", "symbol": "sendDigest", "patterns": ["fetch"]}]}
    flow = extract_facts(SRC, spec)["flows"][0]
    assert flow["status"] == "unknown"
    assert "language not supported: .ts" in flow["reason"] and "regex_only" in flow["reason"]


def test_declaration_strategy_needing_an_ast_refuses_a_foreign_language():
    decls = SourceScanner(SRC).tool_declarations("ui/client.ts", {"strategy": "registry_dict", "symbol": "TOOLS"})
    assert decls[0]["status"] == "unknown" and "language not supported: .ts" in decls[0]["reason"]


# --------------------------------------------------------------------------- #
# P0-2  declared > annotation > heuristic > unknown
# --------------------------------------------------------------------------- #

def test_declaration_beats_the_heuristic_and_says_so(registry_doc):
    tools = {t.name: t for t in registry_doc.all_tools()}
    traverse = tools["vault_traverse"]
    assert traverse.classification == Operation.READ and traverse.operations == ["READ"]
    assert traverse.classification_basis == "declared"
    assert traverse.provenance["classification"] == "declared:profile"
    # a declaration is the author speaking, not an observation
    assert traverse.knowledge_state == KnowledgeState.ASSUMED


def test_declaration_in_the_source_registry_is_used_for_the_configured_tool(registry_doc):
    mine = {t.name: t for t in registry_doc.all_tools()}["vault_mine_note"]
    assert mine.operations == ["CREATE"] and mine.egress is False and mine.sensitive_source is True
    assert mine.provenance["classification"] == "declared:source"


def test_declaration_against_the_servers_annotation_is_recorded_not_silently_won(registry_doc):
    mine = {t.name: t for t in registry_doc.all_tools()}["vault_mine_note"]
    conflict = mine.contract["declaration_vs_annotation"]
    assert conflict[0]["annotation"] == "readOnlyHint=true" and conflict[0]["declared"] == ["CREATE"]
    assert mine.knowledge_state == KnowledgeState.CONTRADICTORY
    assert "not resolved" in mine.provenance["classification_conflict"]


def test_declared_egress_false_removes_the_heuristic_transmit():
    t = classify_tool(_tool("vault_send_digest", "Send the digest to the configured webhook."))
    assert t.egress and "TRANSMIT" in t.operations
    declared = classify_tool(_tool("vault_send_digest", "Send the digest to the configured webhook."),
                             declared={"egress": False})
    assert declared.egress is False and "TRANSMIT" not in declared.operations


def test_invalid_declaration_is_reported_and_does_not_silently_apply():
    t = classify_tool(_tool("vault_thing"), declared={"operations": ["TELEPORT"], "egress": "yes"})
    assert "TELEPORT" not in t.operations
    problems = t.provenance["declaration_problems"]
    assert "TELEPORT" in problems and "egress must be true or false" in problems


def test_unknown_stays_unknown_without_a_declaration():
    t = classify_tool(_tool("vault_frobnicate", "Frobnicate the palace."))
    assert t.classification == Operation.UNKNOWN and t.knowledge_state == KnowledgeState.UNKNOWN
    assert t.provenance["classification"] == "definition:none"


# --------------------------------------------------------------------------- #
# P1-4 / P1-5  lexicon and server kinds as data
# --------------------------------------------------------------------------- #

def test_base_lexicon_reproduces_the_frozen_patterns():
    """The move of the lexicon into data must not change a single expression."""
    with open(os.path.join(REGRESSION, "lexicon_baseline.json"), encoding="utf-8") as fh:
        frozen = json.load(fh)
    lex = base_lexicon()
    for key, group, name in (("_EXEC", "operations", "exec"), ("_DELETE", "operations", "delete"),
                             ("_CREATE", "operations", "create"), ("_WRITE", "operations", "write"),
                             ("_READ", "operations", "read"), ("_EXEC_DESC", "signals", "exec_description"),
                             ("_PUBLISH", "signals", "publish"), ("_TRANSMIT", "signals", "transmit"),
                             ("_SENSITIVE", "signals", "sensitive"), ("_UNTRUSTED", "signals", "untrusted"),
                             ("_EGRESS", "signals", "egress")):
        assert lex.rx(group, name).pattern == frozen[key], f"{group}.{name} drifted from the frozen lexicon"
    assert sorted(lex.network_kinds) == sorted(frozen["_NETWORK_KINDS"])
    assert [(k, rx.pattern) for k, rx in lex.server_kinds()] == [tuple(x) for x in frozen["_KNOWN_KINDS"]]


def test_classification_of_the_existing_stand_is_bit_for_bit_unchanged(stand_doc):
    with open(os.path.join(REGRESSION, "genai_invest_stand.classification.json"), encoding="utf-8") as fh:
        expected = json.load(fh)
    actual = {"server_kinds": {s.name: s.kind for s in stand_doc.servers},
              "tools": {t.qualified_name: {"classification": t.classification.value,
                                           "operations": sorted(t.operations),
                                           "egress": t.egress, "destructive": t.destructive,
                                           "sensitive_source": t.sensitive_source,
                                           "untrusted_input": t.untrusted_input,
                                           "classification_basis": t.classification_basis,
                                           "knowledge_state": t.knowledge_state.value,
                                           "provenance_classification": t.provenance.get("classification")}
                        for s in stand_doc.servers for t in s.tools}}
    assert actual == expected


def test_profile_lexicon_teaches_domain_verbs():
    lex = load_lexicon(_profile())
    plain = classify_tool(_tool("vault_dissolve_wing", "Dissolve a whole wing of the palace."))
    assert plain.classification == Operation.UNKNOWN            # the engine does not guess a domain verb
    taught = classify_tool(_tool("vault_dissolve_wing", "Dissolve a whole wing of the palace."), lexicon=lex)
    assert taught.classification == Operation.DELETE and taught.destructive


def test_lexicon_version_travels_with_the_report(registry_doc):
    lexicon = registry_doc.meta["reproducibility"]["lexicon"]
    assert lexicon["base_version"] == base_lexicon().version and lexicon["modified"] is True
    assert lexicon["lexicon_version"] != lexicon["base_version"]
    assert "operations.write" in lexicon["modifications"]["extend"]


def test_server_kinds_come_from_the_lexicon_and_a_profile_may_add_one():
    from mcp_audit.discovery.config_parser import infer_kind
    assert infer_kind("db", "npx", ["server-postgres"], None) == "postgres"
    assert infer_kind("vault", "python", ["-m", "vault.server"], None) == "generic"
    lex = load_lexicon(_profile())
    assert infer_kind("vault", "python", ["-m", "vault.server"], None, lex) == "palace"


def test_broken_lexicon_is_refused_with_the_category_named():
    with pytest.raises(LexiconError) as exc:
        load_lexicon({"profile_id": "x", "lexicon": {"override": {"operations": {"read": {"patterns": ["("]}}}}})
    assert "operations.read" in str(exc.value)
    with pytest.raises(LexiconError):
        load_lexicon({"profile_id": "x", "lexicon": {"extend": {"nonsense": {}}}})


def test_build_pattern_accepts_the_shorthand():
    assert build_pattern(["a", "b"]) == r"\b(a|b)\b"
    assert build_pattern({"patterns": ["x|y"]}) == "x|y"


# --------------------------------------------------------------------------- #
# P0-3  lint-profile
# --------------------------------------------------------------------------- #

@pytest.mark.parametrize("name,root", [("genai_invest_stand", ROOT), ("rest_native_agent", os.path.join(HERE, "fixtures", "rest_native_agent", "src"))])
def test_reference_profiles_lint_clean(name, root):
    with open(os.path.join(ROOT, "profiles", f"{name}.json"), encoding="utf-8") as fh:
        profile = json.load(fh)
    report = lint_profile(profile, root=root)
    assert report.errors == [], report.text()
    assert report.ok


def test_new_stand_profile_lints_clean_against_its_sources():
    report = lint_profile(_profile(), root=SRC)
    assert report.errors == [] and report.warnings == [], report.text()
    assert report.plan["entries"], "the report must say which rules the profile opens"


def test_lint_reports_the_typo_the_engine_would_report_as_unknown():
    profile = _profile()
    profile["source_facts"]["flows"][0]["symbol"] = "Palace.add_drawer"
    profile["source_facts"]["flows"][2]["patterns"] = ["WHERE subject_id = (%s"]
    profile["source_facts"]["flows"][3]["rule_refs"] = ["MEM-99"]
    profile["source_facts"]["flows"][1]["boundary"] = "VB-nope"
    profile["source_facts"]["tool_declarations"][0]["path"] = "srver.py"
    report = lint_profile(profile, root=SRC)
    text = report.text()
    assert "'Palace.add_drawer' not found in palace.py" in text
    assert "invalid regex" in text
    assert "'MEM-99' is not a rule in the catalogue" in text
    assert "'VB-nope' is not declared in boundaries[]" in text
    assert "'srver.py' does not exist" in text
    assert len(report.errors) == 5


def test_lint_warns_about_a_section_the_engine_ignores():
    profile = _profile()
    profile["memory_store"] = []          # typo: the section is 'memory_stores'
    report = lint_profile(profile)
    assert report.ok                       # a warning does not fail the run
    assert any("unknown profile section" in p.message for p in report.warnings)


def test_lint_profile_cli_exit_codes(tmp_path, capsys):
    assert cli_main(["lint-profile", os.path.join(STAND, "profile.json"), "--root", SRC]) == 0
    broken = _profile()
    broken["source_facts"]["flows"][0]["patterns"] = ["("]
    path = tmp_path / "broken.json"
    path.write_text(json.dumps(broken), encoding="utf-8")
    assert cli_main(["lint-profile", str(path)]) == 1
    assert cli_main(["lint-profile", str(tmp_path / "nope.json")]) == 4
    out = capsys.readouterr().out
    assert "invalid regex" in out


def test_lint_profile_plan_counts_rules_per_source():
    report = lint_profile(_profile(), root=SRC, sources=["mcp_inventory", "policy_snapshot"])
    planned = {e["rule_id"] for e in report.plan["entries"] if e["status"] == "planned"}
    assert {"MEM-01", "EGRESS-01", "TOOL-02"} <= planned
    assert "TOOL-01" not in planned                      # no baseline was bound
    assert "baseline" in report.text()


# --------------------------------------------------------------------------- #
# P2-6  adapter plugins
# --------------------------------------------------------------------------- #

def test_adapter_plugin_registers_a_new_kind_from_outside_the_package():
    assert load_plugin("tests.fixtures.plugin_adapter:NotesAdapter") == "notes_snapshot"
    assert "notes_snapshot" in known_kinds()


def test_adapter_plugin_from_the_manifest_reaches_the_plan():
    m = Manifest(target={"id": "plugin", "build_ref": "f", "environment": "fixture"}, mode=RunMode.OFFLINE,
                 adapter_plugins=["tests.fixtures.plugin_adapter:NotesAdapter"],
                 adapters=[AdapterBinding("notes", "notes_snapshot", {"note": "hello"}, base_dir=STAND)],
                 base_dir=STAND)
    doc = Orchestrator(m).run()
    statuses = {a.kind: a.status for a in doc.adapters}
    assert statuses["notes_snapshot"] == "available"
    assert doc.meta["adapter_plugins"]["loaded"] == ["notes_snapshot"]


def test_a_plugin_that_does_not_load_is_reported_not_ignored():
    kinds, problems = load_plugins(["mcp_audit.nowhere:Nope", "mcp_audit.models:AuditDocument"])
    assert kinds == []
    assert any("ModuleNotFoundError" in p for p in problems)
    assert any("not a subclass" in p for p in problems)


# --------------------------------------------------------------------------- #
# the whole stand: same rules, same report format, no engine change
# --------------------------------------------------------------------------- #

def test_third_topology_is_audited_by_the_same_rules(registry_doc):
    outcomes = {r.rule_id: r.control_outcome for r in registry_doc.control_results}
    assert outcomes["MEM-01"] == ControlOutcome.PASS
    assert outcomes["MEM-03"] == ControlOutcome.PASS
    assert outcomes["MEM-05"] == ControlOutcome.PASS
    assert outcomes["TOOL-02"] != ControlOutcome.NOT_EVALUATED     # registry + config = two contracts to compare
    assert outcomes["EGRESS-01"] == ControlOutcome.FAIL            # the engine can still contradict the author
    evaluated = [r for r in registry_doc.control_results
                 if r.control_outcome not in (ControlOutcome.NOT_EVALUATED, ControlOutcome.NOT_APPLICABLE)]
    assert len(evaluated) >= 10
    assert validate_document(json.loads(emit_json(registry_doc))) == []


def test_source_declared_tools_are_reconciled_with_the_configured_catalogue(registry_doc):
    pairs = {r["pair"] for r in registry_doc.inventory_reconciliation}
    assert "configured/source_defined" in pairs
    contracts = [r for r in registry_doc.inventory_reconciliation if r["kind"].startswith("contract_")]
    assert {r["tool_name"] for r in contracts} >= {"vault_mine_note", "vault_traverse", "vault_dissolve_wing"}
