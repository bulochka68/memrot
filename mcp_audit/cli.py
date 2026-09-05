"""Command-line interface.

Modes are explicit (TZ §14): offline | live-inventory | trace-review | controlled-validation | baseline-comparison
(legacy passive/active/drift are accepted as aliases).  Exit codes separate an
audit error from "no violations" and incompleteness from violations:

    0  completed, no violations observed in scope
    1  findings present (confirmed)
    2  assessment partial / undetermined (an unknown mandatory control is never an allow)
    3  drift detected (baseline comparison)
    4  audit error / invalid input
"""
from __future__ import annotations

import argparse
import json
import os
import sys
from typing import Any, Dict, List, Optional

from . import AUDIT_SCHEMA_VERSION, ENGINE_VERSION, RULESET_VERSION
from .models import AccessProfile, RunMode, coerce_mode
from .adapters import AdapterBinding
from .manifest import load_manifest, wrap_legacy_config
from .orchestrator import Orchestrator
from .active import IsolationGuard
from .reporting import emit_json, emit_markdown, emit_jsonl, emit_obsec, save_baseline, load_baseline
from .validation import validate_document
from .control_rules import catalog_dict
from .migration import load_legacy_audit

EXIT_OK, EXIT_FINDINGS, EXIT_INCOMPLETE, EXIT_DRIFT, EXIT_ERROR = 0, 1, 2, 3, 4
MODE_CHOICES = ["offline", "live-inventory", "trace-review", "controlled-validation", "baseline-comparison",
                "passive", "active", "drift"]


def _add_common(p: argparse.ArgumentParser) -> None:
    p.add_argument("target", help="v2 manifest (YAML/JSON) or a plain MCP client config (wrapped automatically)")
    p.add_argument("--mode", choices=MODE_CHOICES, default=None, help="execution mode (default: manifest inspection.mode or offline)")
    p.add_argument("--access-profile", choices=[a.value for a in AccessProfile], default=None)
    p.add_argument("--profile", help="system profile (JSON/YAML) with component/flow declarations")
    p.add_argument("--snapshot", help="tools snapshot JSON of an earlier handshake (legacy config only)")
    p.add_argument("--context-root", help="directory to scan for agent context files (CLAUDE.md, ...)")
    p.add_argument("--source-root", help="bind a source_snapshot adapter to this source tree")
    p.add_argument("--source-facts", help="bind a source_snapshot adapter to a pre-extracted facts file")
    p.add_argument("--policy", help="bind a policy_snapshot adapter to this file")
    p.add_argument("--memory-events", help="bind a memory_event_snapshot adapter to this file")
    p.add_argument("--trace", help="bind a trace adapter to this JSONL file")
    p.add_argument("--deployment", help="bind a deployment adapter to this compose/JSON file")
    p.add_argument("--fixtures", help="bind a control_fixtures adapter to this file")
    p.add_argument("--required-controls", help="comma-separated rule ids to evaluate (default: all)")
    p.add_argument("--timeout", type=float, default=20.0)
    p.add_argument("--cwd", help="working directory for spawned stdio servers")
    p.add_argument("--identity", help="label of the identity/role used for live inventory")


def _extra_adapters(args: argparse.Namespace) -> List[AdapterBinding]:
    out: List[AdapterBinding] = []
    cwd = os.getcwd()
    if args.source_root:
        out.append(AdapterBinding("source", "source_snapshot", {"root": os.path.abspath(args.source_root)}, base_dir=cwd))
    elif args.source_facts:
        out.append(AdapterBinding("source", "source_snapshot", {"path": os.path.abspath(args.source_facts)}, base_dir=cwd))
    if args.policy:
        out.append(AdapterBinding("policy", "policy_snapshot", {"path": os.path.abspath(args.policy)}, base_dir=cwd))
    if args.memory_events:
        out.append(AdapterBinding("memory-events", "memory_event_snapshot", {"path": os.path.abspath(args.memory_events)}, base_dir=cwd))
    if args.trace:
        out.append(AdapterBinding("trace", "trace", {"path": os.path.abspath(args.trace)}, base_dir=cwd))
    if args.deployment:
        out.append(AdapterBinding("deployment", "deployment", {"path": os.path.abspath(args.deployment)}, base_dir=cwd))
    if args.fixtures:
        out.append(AdapterBinding("fixtures", "control_fixtures", {"path": os.path.abspath(args.fixtures)}, base_dir=cwd))
    return out


def _load_target(args: argparse.Namespace):
    mode = coerce_mode(args.mode) if args.mode else None
    manifest = load_manifest(args.target, mode_override=mode)
    if manifest.legacy_wrapped:
        mcp = manifest.adapter("mcp-config")
        if args.snapshot:
            mcp.binding["snapshot"] = os.path.abspath(args.snapshot)
        if args.context_root:
            mcp.binding["context_root"] = os.path.abspath(args.context_root)
        if args.identity:
            mcp.binding["identity"] = args.identity
    if args.access_profile:
        manifest.access_profile = AccessProfile(args.access_profile)
    if args.profile:
        manifest.profile_ref = os.path.abspath(args.profile)
    if args.required_controls:
        manifest.required_controls = [r.strip() for r in args.required_controls.split(",") if r.strip()]
    manifest.adapters.extend(_extra_adapters(args))
    return manifest


def _exit_code(doc, gate: bool) -> int:
    v = doc.verdict or {}
    if doc.status == "failed":
        return EXIT_ERROR
    if not gate:
        return EXIT_OK
    if v.get("security_conclusion") == "findings_present":
        return EXIT_FINDINGS
    if v.get("assessment_state") != "complete_for_scope" or v.get("security_conclusion") != "no_violations_observed":
        return EXIT_INCOMPLETE
    return EXIT_OK


def cmd_audit(args: argparse.Namespace) -> int:
    try:
        manifest = _load_target(args)
    except (ValueError, FileNotFoundError, RuntimeError) as e:
        print(f"error: {e}", file=sys.stderr)
        return EXIT_ERROR
    guard = None
    if manifest.mode == RunMode.CONTROLLED_VALIDATION:
        guard = IsolationGuard(sandbox=args.sandbox, allow_destructive=args.allow_destructive)
    orch = Orchestrator(manifest)
    doc = orch.run(timeout=args.timeout, cwd=args.cwd, use_mcp_scan=args.mcp_scan, guard=guard,
                   baseline_path=args.baseline, approvals_path=args.approvals)
    out = emit_json(doc)
    errors = validate_document(json.loads(out))
    if errors:
        print("report validation errors: " + "; ".join(errors[:10]), file=sys.stderr)
    if args.json:
        with open(args.json, "w", encoding="utf-8") as fh:
            fh.write(out)
    if args.md:
        with open(args.md, "w", encoding="utf-8") as fh:
            fh.write(emit_markdown(doc))
    if args.jsonl:
        with open(args.jsonl, "w", encoding="utf-8") as fh:
            fh.write(emit_jsonl(doc))
    if args.obsec:
        with open(args.obsec, "w", encoding="utf-8") as fh:
            fh.write(emit_obsec(doc))
    if args.baseline_out:
        save_baseline(doc, args.baseline_out)
    if not args.json or args.stdout:
        print(out)
    v = doc.verdict or {}
    status = {"status": doc.status, "assessment_state": v.get("assessment_state"), "security_conclusion": v.get("security_conclusion"),
              "confirmed_findings": len(v.get("confirmed_finding_refs") or []), "hypotheses": len(v.get("hypothesis_finding_refs") or []),
              "unresolved_controls": v.get("unresolved_controls"), "validation_errors": len(errors),
              "exit_code": (EXIT_ERROR if errors and args.strict else _exit_code(doc, args.gate))}
    print(json.dumps(status, ensure_ascii=False), file=sys.stderr)
    return status["exit_code"]


def cmd_baseline(args: argparse.Namespace) -> int:
    try:
        manifest = _load_target(args)
    except (ValueError, FileNotFoundError, RuntimeError) as e:
        print(f"error: {e}", file=sys.stderr)
        return EXIT_ERROR
    doc = Orchestrator(manifest).run(timeout=args.timeout, cwd=args.cwd)
    baseline = save_baseline(doc, args.output)
    print(f"baseline written to {args.output}: {len(baseline['hash_baseline'])} definitions; approval_state={baseline['approval_state']}", file=sys.stderr)
    return EXIT_OK if doc.status != "failed" else EXIT_ERROR


def cmd_drift(args: argparse.Namespace) -> int:
    args.mode = args.mode or "baseline-comparison"
    try:
        manifest = _load_target(args)
    except (ValueError, FileNotFoundError, RuntimeError) as e:
        print(f"error: {e}", file=sys.stderr)
        return EXIT_ERROR
    doc = Orchestrator(manifest).run(timeout=args.timeout, cwd=args.cwd, baseline_path=args.baseline, approvals_path=args.approvals)
    print(json.dumps(doc.drift, indent=2, ensure_ascii=False))
    if doc.status == "failed":
        return EXIT_ERROR
    if args.fail_on_drift:
        if doc.drift.get("clean") is None:
            return EXIT_INCOMPLETE
        if not doc.drift.get("clean"):
            return EXIT_DRIFT
    return EXIT_OK


def cmd_validate(args: argparse.Namespace) -> int:
    with open(args.report, "r", encoding="utf-8") as fh:
        data = json.load(fh)
    errors = validate_document(data)
    for e in errors:
        print(f"- {e}")
    print(f"{len(errors)} error(s)", file=sys.stderr)
    return EXIT_OK if not errors else EXIT_ERROR


def cmd_migrate(args: argparse.Namespace) -> int:
    try:
        doc = load_legacy_audit(args.report)
    except ValueError as e:
        print(f"error: {e}", file=sys.stderr)
        return EXIT_ERROR
    from .static_analysis import run_static_analysis
    from .classification import classify_all, resolve_effective_access, score_tool
    from .correlation import build_summary, build_verdict, assess_trifecta, capability_indicators
    from .coverage import build_coverage
    from .evidence import EvidenceStore
    store = EvidenceStore(doc)
    for s in doc.servers:
        resolve_effective_access(s)
    classify_all(doc)
    run_static_analysis(doc, store)
    for t in doc.all_tools():
        s = doc.server(t.server)
        score_tool(t, server_kind=s.kind if s else "generic")
    doc.trifecta = assess_trifecta(doc)
    doc.summary["capability_indicators"] = capability_indicators(doc, store)
    build_coverage(doc, [])
    doc.summary = {**build_summary(doc), "capability_indicators": doc.summary["capability_indicators"]}
    doc.status = "partial"
    doc.verdict = build_verdict(doc, [])
    doc.verdict["assessment_state"] = "partial"
    doc.verdict["limitations"].append("migrated document: no control rules were evaluated; only inventory, signals and capability indicators")
    out = emit_json(doc)
    if args.output:
        with open(args.output, "w", encoding="utf-8") as fh:
            fh.write(out)
        print(f"migrated -> {args.output}", file=sys.stderr)
    else:
        print(out)
    return EXIT_OK


def rules_markdown() -> str:
    cat = catalog_dict()
    L = [f"# Каталог контрольных требований (ruleset {cat['ruleset_version']})", "",
         "Сгенерировано командой `python -m mcp_audit rules --markdown`. Правила не содержат имён конкретного стенда: привязки живут в профилях.", "",
         "| ID | Версия | Домен | Этап | Название | Требование | Критерий результата | Нужные источники (альтернативы) |",
         "|---|---|---|---|---|---|---|---|"]
    for r in cat["rules"]:
        srcs = " / ".join("+".join(alt) for alt in r["required_sources"])
        L.append(f"| {r['rule_id']} | {r['version']} | {r['domain']} | {r['stage']} | {r['title']} | {r['requirement']} | {r['criterion']} | {srcs} |")
    L += ["", "## Подробности", ""]
    for r in cat["rules"]:
        L += [f"### {r['rule_id']} — {r['title']}", "",
              f"- Ожидаемый инвариант: {r['expected_invariant']}",
              f"- Допустимые методы: {', '.join(r['methods'])}",
              f"- Критерий исправления: {r['remediation_criterion'] or '—'}",
              f"- Приоритет по умолчанию: {r['default_priority']}"]
        if r["known_false_positives"]:
            L.append("- Известные ложные срабатывания: " + "; ".join(r["known_false_positives"]))
        if r["limitations"]:
            L.append("- Ограничения: " + "; ".join(r["limitations"]))
        if r["external_refs"]:
            L.append("- Внешние ориентиры: " + "; ".join(f"[{e['name']}]({e['url']})" + (f" — {e['note']}" if e.get("note") else "") for e in r["external_refs"]))
        L.append("")
    return "\n".join(L) + "\n"


def cmd_rules(args: argparse.Namespace) -> int:
    cat = catalog_dict()
    if args.json_out:
        print(json.dumps(cat, indent=2, ensure_ascii=False))
        return EXIT_OK
    if args.markdown:
        print(rules_markdown(), end="")
        return EXIT_OK
    print(f"ruleset {cat['ruleset_version']}")
    for r in cat["rules"]:
        print(f"{r['rule_id']:<10} v{r['version']:<7} [{r['domain']:<14}] stage {r['stage']}  {r['title']}")
        if args.verbose:
            print(f"    требование: {r['requirement']}")
            print(f"    источники:  {r['required_sources']}")
    return EXIT_OK


def cmd_source_snapshot(args: argparse.Namespace) -> int:
    from .adapters.source_snapshot import extract_facts
    from .manifest import load_profile
    profile = load_profile(args.profile, os.getcwd())
    facts = extract_facts(args.root, profile.get("source_facts") or {},
                          captured_from={"commit": args.commit, "repository": args.repository} if args.commit or args.repository else None)
    text = json.dumps(facts, indent=2, ensure_ascii=False)
    if args.output:
        with open(args.output, "w", encoding="utf-8") as fh:
            fh.write(text)
        print(f"source facts written to {args.output}: {len(facts['tool_declarations'])} declaration(s), {len(facts['flows'])} flow(s)", file=sys.stderr)
    else:
        print(text)
    return EXIT_OK


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="mcp_audit",
                                     description=f"Agent security audit subsystem v{ENGINE_VERSION} (schema {AUDIT_SCHEMA_VERSION}, ruleset {RULESET_VERSION})")
    sub = parser.add_subparsers(dest="command", required=True)

    pa = sub.add_parser("audit", help="run the audit")
    _add_common(pa)
    pa.add_argument("--sandbox", action="store_true", help="declare sandbox for controlled validation (intent, not proof)")
    pa.add_argument("--allow-destructive", action="store_true", help="run destructive control cases (default: skipped)")
    pa.add_argument("--mcp-scan", action="store_true", help="also run Invariant Labs mcp-scan (not in offline mode)")
    pa.add_argument("--baseline", help="compare definitions/policy against this baseline")
    pa.add_argument("--approvals", help="approval registry for baseline changes")
    pa.add_argument("--json", help="write the audit JSON to this path")
    pa.add_argument("--md", help="write the Markdown report to this path")
    pa.add_argument("--jsonl", help="write a JSONL export to this path")
    pa.add_argument("--obsec", help="write the ObSec export to this path")
    pa.add_argument("--baseline-out", help="also write a baseline snapshot")
    pa.add_argument("--stdout", action="store_true", help="print JSON even when --json is set")
    pa.add_argument("--gate", action="store_true", help="exit 1 on confirmed findings, 2 on incomplete assessment")
    pa.add_argument("--strict", action="store_true", help="exit 4 when the report fails validation")
    pa.set_defaults(func=cmd_audit)

    pb = sub.add_parser("baseline", help="write a baseline snapshot")
    _add_common(pb)
    pb.add_argument("-o", "--output", required=True)
    pb.set_defaults(func=cmd_baseline)

    pd = sub.add_parser("drift", help="compare against a baseline (baseline-comparison mode)")
    _add_common(pd)
    pd.add_argument("--baseline", required=True)
    pd.add_argument("--approvals")
    pd.add_argument("--fail-on-drift", action="store_true", help="exit 3 on material change, 2 when not comparable")
    pd.set_defaults(func=cmd_drift)

    pv = sub.add_parser("validate", help="validate a v2 report (structure + referential integrity)")
    pv.add_argument("report")
    pv.set_defaults(func=cmd_validate)

    pm = sub.add_parser("migrate", help="import a legacy audit v1.0/v1.1 into the v2 format")
    pm.add_argument("report")
    pm.add_argument("-o", "--output")
    pm.set_defaults(func=cmd_migrate)

    pr = sub.add_parser("rules", help="print the rule catalogue")
    pr.add_argument("--json", dest="json_out", action="store_true")
    pr.add_argument("--markdown", action="store_true", help="print the catalogue as Markdown (docs/rules_catalog.md)")
    pr.add_argument("-v", "--verbose", action="store_true")
    pr.set_defaults(func=cmd_rules)

    ps = sub.add_parser("source-snapshot", help="extract portable source facts from a source tree using a profile")
    ps.add_argument("--root", required=True)
    ps.add_argument("--profile", required=True)
    ps.add_argument("--commit")
    ps.add_argument("--repository")
    ps.add_argument("-o", "--output")
    ps.set_defaults(func=cmd_source_snapshot)
    return parser


def main(argv: Optional[List[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
