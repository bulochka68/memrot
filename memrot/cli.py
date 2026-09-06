"""Command-line interface.

Exit codes (mirrors mcp_audit's convention):

    0  run completed; no CONFIRMED verdicts (or --gate not set)
    1  at least one CONFIRMED verdict                                [only with --gate]
    2  no CONFIRMED, but NOT_EVALUATED/INVALID/ERROR present (incomplete coverage)  [only with --gate]
    4  config/adapter/catalog fatal error before any variant could run

(3 is reserved for a future phase-2 ASR-regression gate; unused in phase 1.)
"""
from __future__ import annotations

import argparse
import json
import os
import sys
from typing import List, Optional

from . import ATTACK_ENGINE_VERSION, ATTACK_SCHEMA_VERSION, MEMROT_TAGLINE, MEMROT_VERSION, taxonomy, ui
from .adapters.registry import build_adapter
from .audit_bridge import filter_variants_by_audit
from .audit_plan import extract_ranked_findings, select_variants_by_audit
from .catalog.generator import ImportedBankGenerator, LLMMutationGenerator, StaticCatalogGenerator
from .catalog.loader import discover_catalog_files, load_catalog
from .catalog.schema import validate_catalog_file
from .config import TargetBinding, load_config
from .detectors import build_detector
from .models import Channel, ChannelRole, Principal, RunReport, Verdict
from .pipeline import audit_then_attack
from .reporting import emit_html, emit_json, emit_markdown
from .runner import run_adaptive, run_matrix
from .tracer import JSONLTracer

_IMPLEMENTED_GENERATOR_KINDS = ("static_catalog", "llm_mutation")

_PACKAGE_DIR = os.path.dirname(os.path.abspath(__file__))
_DEFAULT_BANK_SOURCES = {
    "garak_dan": os.path.join(_PACKAGE_DIR, "catalog", "imported", "garak_dan"),
    "trustairlab_jailbreak": os.path.join(_PACKAGE_DIR, "catalog", "imported", "trustairlab_jailbreak", "sample.json"),
}

EXIT_OK, EXIT_CONFIRMED, EXIT_INCOMPLETE, EXIT_DRIFT, EXIT_ERROR = 0, 1, 2, 3, 4


def _check_target_adapter(adapter, channels):
    """A real ping (new_session + send), not a key-format check -- matches
    this project's own live-validated adapters, which have no lighter-weight
    health endpoint. Costs one extra turn against a real target, same
    trade-off the config-panel banner is asked to make explicit."""
    if not channels:
        return True, "no channel configured to validate against"
    try:
        principal = channels[0].principal
        session = adapter.new_session(principal)
        adapter.send(principal, session, "ping")
        return True, f"reachable ({adapter.kind})"
    except Exception as exc:
        return False, f"{type(exc).__name__}: {exc}"


def _check_llm(base_url, model, api_key_env):
    from .mutation.llm_client import LLMClient, LLMClientConfig, LLMClientError
    try:
        client = LLMClient(LLMClientConfig(base_url=base_url, model=model, api_key_env=api_key_env))
        client.complete(system="You are a health check.", user="Reply with the single word OK.", max_tokens=5)
        return True, f"reachable ({model})"
    except LLMClientError as exc:
        return False, str(exc)


def _group_key(variant_or_result) -> str:
    rule_ids = getattr(variant_or_result, "rule_ids", None) or []
    if rule_ids:
        return "+".join(sorted(rule_ids))
    return getattr(variant_or_result, "owasp_amg_category", "") or "(untagged)"


def _results_table_rows(results):
    groups: "dict[str, list[int]]" = {}
    for r in results:
        key = _group_key(r)
        bucket = groups.setdefault(key, [0, 0, 0])
        if r.verdict == Verdict.CONFIRMED:
            bucket[0] += 1
        elif r.verdict == Verdict.CLEAN:
            bucket[1] += 1
        else:
            bucket[2] += 1
    rows = [(key, c, cl, e) for key, (c, cl, e) in sorted(groups.items())]
    total_c = sum(r[1] for r in rows)
    total_cl = sum(r[2] for r in rows)
    total_e = sum(r[3] for r in rows)
    return rows, ("Total", total_c, total_cl, total_e)


def _vulnerable_descriptions(rows) -> List[str]:
    lines = []
    for key, confirmed, _clean, _excluded in rows:
        if confirmed == 0:
            continue
        desc = ""
        if taxonomy.is_known_category(key):
            desc = taxonomy.category(key).description
        lines.append(f"{key}: {desc}" if desc else key)
    return lines


def cmd_run(args: argparse.Namespace) -> int:
    fancy = ui.fancy_enabled(getattr(args, "no_fancy", False), getattr(args, "fancy", False))
    if fancy:
        ui.print_banner(MEMROT_VERSION, MEMROT_TAGLINE)
        print()
    try:
        config = load_config(args.config)
    except (ValueError, FileNotFoundError, RuntimeError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return EXIT_ERROR

    generator_kind = "llm_mutation" if args.mutate else config.generator.kind
    if generator_kind not in _IMPLEMENTED_GENERATOR_KINDS:
        print(f"error: generator.kind={generator_kind!r} is not implemented "
             f"(available: {list(_IMPLEMENTED_GENERATOR_KINDS)})", file=sys.stderr)
        return EXIT_ERROR

    catalog_paths = args.catalog if args.catalog else config.resolve_catalog_paths()
    if not catalog_paths and not args.catalog_bank:
        print("error: no catalog_paths in config, no --catalog, and no --catalog-bank given", file=sys.stderr)
        return EXIT_ERROR

    try:
        seed_variants = StaticCatalogGenerator(catalog_paths).generate() if catalog_paths else []
        if args.catalog_bank:
            bank_source = args.catalog_bank_source or _DEFAULT_BANK_SOURCES.get(args.catalog_bank)
            if not bank_source:
                raise ValueError(f"--catalog-bank {args.catalog_bank!r} has no default source; "
                                 "pass --catalog-bank-source explicitly")
            seed_variants = seed_variants + ImportedBankGenerator(
                args.catalog_bank, bank_source,
                sample_size=args.catalog_bank_sample_size, seed=args.catalog_bank_seed,
            ).generate()
        mutation_failures: List[str] = []
        if generator_kind == "llm_mutation":
            gen_options = dict(config.generator.options)
            if args.mutate:
                gen_options["techniques"] = [t.strip() for t in args.mutate.split(",") if t.strip()]
            if args.mutation_base_url:
                gen_options["base_url"] = args.mutation_base_url
            if args.mutation_model:
                gen_options["model"] = args.mutation_model
            if args.mutation_api_key_env:
                gen_options["api_key_env"] = args.mutation_api_key_env
            mutation_generator = LLMMutationGenerator(seed_variants, **gen_options)
            variants = mutation_generator.generate()
            mutation_failures = mutation_generator.failures
        else:
            variants = seed_variants

        if args.taxonomy_filter:
            variants = [v for v in variants if v.owasp_amg_category == args.taxonomy_filter]

        adapter = build_adapter(config.target)

        detector_kind = config.detector.kind
        detector_options = dict(config.detector.options)
        if args.judge_base_url or args.judge_model:
            # a full kind switch, not an override: config.detector.options was authored
            # for whatever detector_kind the config file itself declared (e.g. LiteralDetector's
            # case_sensitive), and LLMJudgeDetector's constructor rejects unknown kwargs outright.
            detector_kind = "llm_judge"
            detector_options = {}
            if args.judge_base_url:
                detector_options["base_url"] = args.judge_base_url
            if args.judge_model:
                detector_options["model"] = args.judge_model
            if args.judge_api_key_env:
                detector_options["api_key_env"] = args.judge_api_key_env
        detector = build_detector(detector_kind, detector_options)
    except (ValueError, FileNotFoundError, RuntimeError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return EXIT_ERROR

    if fancy:
        config_lines = [
            f"Target:       {config.target.kind} @ {config.target.binding.get('base_url', '(in-process)')}",
        ]
        auth_mode = config.target.binding.get("auth_mode")
        if auth_mode:
            config_lines[-1] += f" (auth_mode={auth_mode})"
        if args.mutation_base_url and args.mutation_model:
            config_lines.append(f"Mutation LLM: {args.mutation_model} via {args.mutation_base_url}")
        if args.attacker_base_url and args.attacker_model:
            config_lines.append(f"Attacker LLM: {args.attacker_model} via {args.attacker_base_url}")
        if args.judge_base_url and args.judge_model:
            config_lines.append(f"Judge LLM:    {args.judge_model} via {args.judge_base_url}")
        catalog_desc = f"{len(variants)} variant(s) from {len(catalog_paths)} path(s)"
        if generator_kind == "llm_mutation":
            catalog_desc += f", mutation techniques: {args.mutate or ','.join(config.generator.options.get('techniques', []))}"
        config_lines.append(f"Catalog:      {catalog_desc}")
        config_lines.append(f"Detector:     {detector_kind}")
        if audit_path := (args.audit or config.audit_path):
            config_lines.append(f"Audit-driven: {args.audit_mode or config.audit_mode} ({audit_path})")
        config_lines.append(f"Gate:         {'enabled' if getattr(args, 'gate', False) else 'disabled'}")
        ui.print_panel("Run Configuration", config_lines)
        print()

        checks = [ui.ModelCheck(f"Target ({config.target.kind})", lambda: _check_target_adapter(adapter, config.channels))]
        if args.mutation_base_url and args.mutation_model:
            checks.append(ui.ModelCheck(f"Mutation LLM ({args.mutation_model})",
                                        lambda: _check_llm(args.mutation_base_url, args.mutation_model, args.mutation_api_key_env)))
        if args.attacker_base_url and args.attacker_model:
            checks.append(ui.ModelCheck(f"Attacker LLM ({args.attacker_model})",
                                        lambda: _check_llm(args.attacker_base_url, args.attacker_model, args.attacker_api_key_env)))
        if args.judge_base_url and args.judge_model:
            checks.append(ui.ModelCheck(f"Judge LLM ({args.judge_model})",
                                        lambda: _check_llm(args.judge_base_url, args.judge_model, args.judge_api_key_env),
                                        required=False))
        if not ui.validate_models(checks):
            print("error: target validation failed -- aborting before spending any attack turns", file=sys.stderr)
            return EXIT_ERROR
        print()

    limitations: List[str] = list(mutation_failures)
    audit_path = args.audit or config.audit_path
    if audit_path:
        audit_mode = args.audit_mode or config.audit_mode
        if audit_mode == "ranked":
            variants, audit_limitations = select_variants_by_audit(
                variants, audit_path, mode="ranked", min_severity=args.audit_min_severity,
                top_n=getattr(args, "audit_top_n", None),
            )
        else:
            variants, audit_limitations = filter_variants_by_audit(variants, audit_path, mode=audit_mode)
        limitations.extend(audit_limitations)

        if fancy and audit_mode == "ranked":
            with open(audit_path, "r", encoding="utf-8") as fh:
                audit_doc = json.load(fh)
            ranked = extract_ranked_findings(audit_doc, min_severity=args.audit_min_severity)
            ui.print_audit_summary(ranked, [v.id for v in variants[:5]], audit_limitations)
            print()

    if fancy:
        ui.print_legend()
        print()

    out_dir = args.out
    trace_path = os.path.join(out_dir, "trace.jsonl") if out_dir else None
    if out_dir:
        os.makedirs(out_dir, exist_ok=True)
    tracer = JSONLTracer(path=trace_path)
    try:
        if getattr(args, "adaptive", False):
            if not args.attacker_base_url or not args.attacker_model:
                print("error: --adaptive requires --attacker-base-url and --attacker-model", file=sys.stderr)
                return EXIT_ERROR
            from .mutation.llm_client import LLMClient, LLMClientConfig
            attacker_llm = LLMClient(LLMClientConfig(
                base_url=args.attacker_base_url, model=args.attacker_model,
                api_key_env=args.attacker_api_key_env,
            ))
            from .models import RunReport as _RunReport, default_run_id
            from .reporting.aggregate import aggregate
            run_id = default_run_id()
            results = []
            on_item, close_progress = ui.make_progress(len(variants), desc="Attacking") if fancy else (None, None)
            for i, seed in enumerate(variants):
                seed_results = run_adaptive(
                    seed, config.channels, adapter, detector, tracer, run_id,
                    attacker_llm=attacker_llm, max_rounds=args.adaptive_max_rounds,
                )
                results.extend(seed_results)
                if on_item is not None:
                    on_item(i, len(variants), seed, seed_results[-1] if seed_results else None)
            if close_progress is not None:
                close_progress()
            report = _RunReport(run_id=run_id, target_id=adapter.kind, results=results,
                               channels=list(config.channels), limitations=limitations,
                               trace_path=tracer.path)
            aggregate(report)
        else:
            on_item, close_progress = ui.make_progress(len(variants), desc="Attacking") if fancy else (None, None)
            report = run_matrix(variants, config.channels, adapter, detector, tracer,
                                reset_between_variants=config.reset_between_variants,
                                progress_hook=on_item)
            if close_progress is not None:
                close_progress()
            report.limitations = limitations + report.limitations
    finally:
        tracer.close()

    if fancy:
        print()
        rows, total_row = _results_table_rows(report.results)
        ui.print_panel("Attack Results", [])
        ui.print_results_table(rows, total_row)
        print()
        vulnerable = _vulnerable_descriptions(rows)
        asr_display = report.overall_asr.display if report.overall_asr else "n/a (0/0)"
        summary_lines = [f"Target failed {asr_display} of attack simulations (CONFIRMED / (CONFIRMED+CLEAN))."]
        if report.counts_by_verdict.get("ERROR") or report.counts_by_verdict.get("INVALID") or report.counts_by_verdict.get("NOT_EVALUATED"):
            summary_lines.append(f"Excluded from ASR (see Status Legend above): {report.counts_by_verdict}")
        summary_lines.append("")
        if vulnerable:
            summary_lines.append("Vulnerable to:")
            summary_lines.extend(f"  {line}" for line in vulnerable)
        else:
            summary_lines.append("No CONFIRMED findings this run (see Known limitations before calling this a clean bill of health).")
        summary_lines.append("")
        summary_lines.append("DISCLAIMER: this report may contain harmful/offensive language from attack payloads.")
        if out_dir:
            summary_lines.append(f"Reports written to: {out_dir}/ (run.json, run.md, trace.jsonl)")
        if getattr(args, "report_html", None):
            summary_lines.append(f"HTML dashboard: {args.report_html}")
        ui.print_panel("Summary", summary_lines)
        print()

    formats = (config.reporting or {}).get("formats", ["json", "markdown"])
    status = _emit_and_status(report, args, formats=formats)
    if fancy:
        print()
        ui.print_footer("Thank you for using MEMROT!")
    return status


def _emit_and_status(report: RunReport, args: argparse.Namespace,
                     formats: Optional[List[str]] = None) -> int:
    formats = formats or ["json", "markdown"]
    out_dir = getattr(args, "out", None)
    json_text = emit_json(report)
    md_text = emit_markdown(report) if "markdown" in formats else None
    html_wanted = bool(getattr(args, "report_html", None) or "html" in formats)
    html_text = emit_html(report) if html_wanted else None

    if out_dir:
        os.makedirs(out_dir, exist_ok=True)
        if "json" in formats:
            with open(os.path.join(out_dir, "run.json"), "w", encoding="utf-8") as fh:
                fh.write(json_text)
        if md_text is not None:
            with open(os.path.join(out_dir, "run.md"), "w", encoding="utf-8") as fh:
                fh.write(md_text)
        if html_text is not None and "html" in formats:
            with open(os.path.join(out_dir, "run.html"), "w", encoding="utf-8") as fh:
                fh.write(html_text)
    else:
        print(json_text)

    report_html = getattr(args, "report_html", None)
    if report_html:
        dirname = os.path.dirname(os.path.abspath(report_html))
        if dirname:
            os.makedirs(dirname, exist_ok=True)
        with open(report_html, "w", encoding="utf-8") as fh:
            fh.write(html_text or emit_html(report))

    counts = report.counts_by_verdict
    status = {
        "run_id": report.run_id,
        "counts_by_verdict": counts,
        "overall_asr": report.overall_asr.display if report.overall_asr else "n/a (0/0)",
        "exit_code": _exit_code(counts, bool(getattr(args, "gate", False))),
    }
    print(json.dumps(status, ensure_ascii=False), file=sys.stderr)
    return status["exit_code"]


def _exit_code(counts, gate: bool) -> int:
    if not gate:
        return EXIT_OK
    if counts.get(Verdict.CONFIRMED.value):
        return EXIT_CONFIRMED
    if counts.get(Verdict.NOT_EVALUATED.value) or counts.get(Verdict.INVALID.value) or counts.get(Verdict.ERROR.value):
        return EXIT_INCOMPLETE
    return EXIT_OK


def cmd_list_catalog(args: argparse.Namespace) -> int:
    try:
        variants = load_catalog(args.catalog, strict=True)
    except (ValueError, FileNotFoundError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return EXIT_ERROR
    if args.rule_id:
        variants = [v for v in variants if args.rule_id in v.rule_ids]
    if args.taxonomy:
        variants = [v for v in variants if v.owasp_amg_category == args.taxonomy]
    print(f"{'id':<38} {'owasp_amg_category':<28} {'rule_ids':<18} {'framing':<24} {'payload':<22} "
         f"{'layer':<14} propagation")
    for v in variants:
        print(f"{v.id:<38} {v.owasp_amg_category or '-':<28} {','.join(v.rule_ids) or '-':<18} "
             f"{v.framing:<24} {v.payload:<22} {v.layer:<14} {v.propagation}")
    print(f"\n{len(variants)} variant(s)", file=sys.stderr)
    return EXIT_OK


def cmd_validate_catalog(args: argparse.Namespace) -> int:
    files = discover_catalog_files(args.paths)
    total_errors = 0
    for path in files:
        errors = validate_catalog_file(path, require_taxonomy=bool(getattr(args, "strict_taxonomy", False)))
        if errors:
            total_errors += len(errors)
            for e in errors:
                print(f"- {e}")
        else:
            print(f"ok: {path}")
    print(f"{len(files)} file(s), {total_errors} error(s)", file=sys.stderr)
    return EXIT_OK if not total_errors else EXIT_ERROR


def cmd_quickstart(args: argparse.Namespace) -> int:
    if not args.url:
        print("error: --url is required (e.g. --url http://localhost:8600/v1)", file=sys.stderr)
        return EXIT_ERROR
    if args.adaptive and (not args.attacker_base_url or not args.attacker_model):
        print("error: --adaptive requires --attacker-base-url and --attacker-model", file=sys.stderr)
        return EXIT_ERROR

    attacker_ref = args.attacker_principal
    victim_ref = args.victim_principal
    if args.cred_attacker_env and os.environ.get(args.cred_attacker_env):
        os.environ[f"MEMROT_CRED_{attacker_ref}"] = os.environ[args.cred_attacker_env]
    if args.cred_victim_env and os.environ.get(args.cred_victim_env):
        os.environ[f"MEMROT_CRED_{victim_ref}"] = os.environ[args.cred_victim_env]

    target = TargetBinding(kind=args.adapter, binding={"base_url": args.url, "model": args.model})
    channels = [
        Channel(role=ChannelRole.ATTACKER, principal=Principal(principal_id=args.attacker_principal,
                                                               credential_ref=attacker_ref)),
        Channel(role=ChannelRole.VICTIM, principal=Principal(principal_id=args.victim_principal,
                                                             credential_ref=victim_ref)),
    ]
    attacker_llm = None
    if args.adaptive:
        from .mutation.llm_client import LLMClient, LLMClientConfig
        attacker_llm = LLMClient(LLMClientConfig(
            base_url=args.attacker_base_url, model=args.attacker_model,
            api_key_env=args.attacker_api_key_env,
        ))
    out_dir = args.out or ".attack"
    os.makedirs(out_dir, exist_ok=True)
    if not args.report_html:
        args.report_html = os.path.join(out_dir, "run.html")
    tracer = JSONLTracer(path=os.path.join(out_dir, "trace.jsonl"))
    try:
        report = audit_then_attack(
            args.audit, target, channels, pool=args.pool, top_n=args.top_n,
            tracer=tracer, adaptive=bool(args.adaptive), attacker_llm=attacker_llm,
            adaptive_max_rounds=args.adaptive_max_rounds, min_severity=args.audit_min_severity,
        )
    except (ValueError, FileNotFoundError, RuntimeError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return EXIT_ERROR
    finally:
        tracer.close()
    args.out = out_dir
    return _emit_and_status(report, args, formats=["json", "markdown", "html"])


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="memrot",
        description=f"Multi-step memory/tool attack harness v{ATTACK_ENGINE_VERSION} (schema {ATTACK_SCHEMA_VERSION})",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    pr = sub.add_parser("run", help="run an attack matrix against a configured target")
    pr.add_argument("--config", required=True, help="run config JSON (target + channels + catalog_paths)")
    pr.add_argument("--catalog", action="append", help="catalog file/dir (repeatable); overrides config.catalog_paths")
    pr.add_argument("--audit", help="an mcp_audit report JSON; filters/prioritizes/ranks the catalog by matched "
                    "rule_ids or owasp_amg_category")
    pr.add_argument("--audit-mode", choices=["filter", "prioritize", "ranked"], default=None,
                    help="'ranked' orders the whole catalog by the audit findings' severity (never drops variants), "
                        "bridged from rule_id to owasp_amg_category where possible (see audit_plan.py)")
    pr.add_argument("--audit-min-severity", choices=["CRITICAL", "HIGH", "MEDIUM", "LOW"], default=None,
                    help="with --audit-mode ranked: only consider findings at or above this severity")
    pr.add_argument("--audit-top-n", type=int, default=None,
                    help="with --audit-mode ranked: keep only the N highest-priority variants")
    pr.add_argument("--adaptive", action="store_true",
                    help="PAIR/TAP-lite loop: rewrite a failed payload and retry (requires attacker LLM)")
    pr.add_argument("--adaptive-max-rounds", type=int, default=3)
    pr.add_argument("--attacker-base-url", help="OpenAI-compatible base_url for the adaptive attacker LLM")
    pr.add_argument("--attacker-model", help="model name for the adaptive attacker LLM")
    pr.add_argument("--attacker-api-key-env", help="env var holding the attacker LLM API key")
    pr.add_argument("--out", help="directory to write run.json / run.md / run.html / trace.jsonl into")
    pr.add_argument("--gate", action="store_true", help="exit 1 on a CONFIRMED verdict, 2 on incomplete coverage")
    pr.add_argument("--taxonomy-filter", help="only run variants tagged with this owasp_amg_category")
    pr.add_argument("--mutate", help="comma-separated mutation technique slugs to apply on top of the loaded "
                    "catalog (e.g. prefix_injection,paraphrase); switches the generator to llm_mutation")
    pr.add_argument("--mutation-base-url", help="OpenAI-compatible base_url for LLM-driven mutation techniques")
    pr.add_argument("--mutation-model", help="model name for LLM-driven mutation techniques")
    pr.add_argument("--mutation-api-key-env", help="env var holding the mutation LLM's API key (optional; "
                    "unset for an unauthenticated local endpoint)")
    pr.add_argument("--judge-base-url", help="OpenAI-compatible base_url for an LLM-judge detector "
                    "(switches the detector to llm_judge, falling back to literal on judge failure)")
    pr.add_argument("--judge-model", help="model name for the LLM-judge detector")
    pr.add_argument("--judge-api-key-env", help="env var holding the judge LLM's API key (optional)")
    pr.add_argument("--report-html", help="also write a self-contained HTML dashboard report to this path")
    pr.add_argument("--catalog-bank", choices=["garak_dan", "trustairlab_jailbreak"],
                    help="also load an external, vendored jailbreak-prompt bank (threat_model="
                        "llm_jailbreak_susceptibility) alongside any --catalog/config catalog_paths")
    pr.add_argument("--catalog-bank-source", help="path override for --catalog-bank (defaults to the "
                    "vendored copy under memrot/catalog/imported/)")
    pr.add_argument("--catalog-bank-sample-size", type=int, default=None,
                    help="randomly (deterministically, see --catalog-bank-seed) subsample the bank to N variants")
    pr.add_argument("--catalog-bank-seed", type=int, default=0, help="seed for --catalog-bank-sample-size")
    pr.add_argument("--fancy", action="store_true",
                    help="force the human-readable banner/panels/progress-bar/table UI even when stdout "
                        "is not a terminal (auto-on for an interactive terminal, auto-off when piped)")
    pr.add_argument("--no-fancy", action="store_true",
                    help="force the plain machine-readable output even in an interactive terminal")
    pr.set_defaults(func=cmd_run)

    pl = sub.add_parser("list-catalog", help="print the loaded catalog's variant inventory")
    pl.add_argument("--catalog", action="append", required=True, help="catalog file/dir (repeatable)")
    pl.add_argument("--rule-id", help="only show variants tagged with this rule_id")
    pl.add_argument("--taxonomy", help="only show variants tagged with this owasp_amg_category")
    pl.set_defaults(func=cmd_list_catalog)

    pv = sub.add_parser("validate-catalog", help="validate one or more catalog files/dirs")
    pv.add_argument("paths", nargs="+")
    pv.add_argument("--strict-taxonomy", action="store_true",
                    help="require owasp_amg_category on memory_poisoning variants and ATLAS or technique_category on all")
    pv.set_defaults(func=cmd_validate_catalog)

    pq = sub.add_parser("quickstart", help="run against any OpenAI-compatible agent without a config file")
    pq.add_argument("--url", required=False, help="target base URL (e.g. http://localhost:8600/v1)")
    pq.add_argument("--model", default="default", help="model / agent name")
    pq.add_argument("--adapter", default="openai_compat",
                    choices=["openai_compat", "genai_invest", "mcp_client", "http_generic"])
    pq.add_argument("--attacker-principal", default="A")
    pq.add_argument("--victim-principal", default="B")
    pq.add_argument("--cred-attacker-env", default=None,
                    help="env var holding the attacker credential (copied onto MEMROT_CRED_<ref>)")
    pq.add_argument("--cred-victim-env", default=None)
    pq.add_argument("--audit", help="mcp_audit JSON; enables ranked mode")
    pq.add_argument("--audit-min-severity", choices=["CRITICAL", "HIGH", "MEDIUM", "LOW"], default=None)
    pq.add_argument("--top-n", type=int, default=None)
    pq.add_argument("--domain", help="domain label; reserved for domain_adaptation when an attacker LLM is configured")
    pq.add_argument("--pool", default="auto", help="auto | neutral | all | <catalog path> "
                    "(auto: invest-stand overlay when --audit profile is genai-invest, else generic)")
    pq.add_argument("--out", default=".attack")
    pq.add_argument("--gate", action="store_true")
    pq.add_argument("--report-html", default=None)
    pq.add_argument("--adaptive", action="store_true")
    pq.add_argument("--adaptive-max-rounds", type=int, default=3)
    pq.add_argument("--attacker-base-url")
    pq.add_argument("--attacker-model")
    pq.add_argument("--attacker-api-key-env")
    pq.set_defaults(func=cmd_quickstart)

    return parser


def main(argv: Optional[List[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
