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

from . import ATTACK_ENGINE_VERSION, ATTACK_SCHEMA_VERSION
from .adapters.registry import build_adapter
from .audit_bridge import filter_variants_by_audit
from .catalog.generator import LLMMutationGenerator, StaticCatalogGenerator
from .catalog.loader import discover_catalog_files, load_catalog
from .catalog.schema import validate_catalog_file
from .config import load_config
from .detectors import build_detector
from .models import Verdict
from .reporting import emit_html, emit_json, emit_markdown
from .runner import run_matrix
from .tracer import JSONLTracer

_IMPLEMENTED_GENERATOR_KINDS = ("static_catalog", "llm_mutation")

EXIT_OK, EXIT_CONFIRMED, EXIT_INCOMPLETE, EXIT_DRIFT, EXIT_ERROR = 0, 1, 2, 3, 4


def cmd_run(args: argparse.Namespace) -> int:
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
    if not catalog_paths:
        print("error: no catalog_paths in config and no --catalog given", file=sys.stderr)
        return EXIT_ERROR

    try:
        seed_variants = StaticCatalogGenerator(catalog_paths).generate()
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
            variants = LLMMutationGenerator(seed_variants, **gen_options).generate()
        else:
            variants = seed_variants

        if args.taxonomy_filter:
            variants = [v for v in variants if v.owasp_amg_category == args.taxonomy_filter]

        adapter = build_adapter(config.target)

        detector_kind = config.detector.kind
        detector_options = dict(config.detector.options)
        if args.judge_base_url or args.judge_model:
            detector_kind = "llm_judge"
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

    limitations: List[str] = []
    audit_path = args.audit or config.audit_path
    if audit_path:
        variants, audit_limitations = filter_variants_by_audit(variants, audit_path, mode=args.audit_mode or config.audit_mode)
        limitations.extend(audit_limitations)

    out_dir = args.out
    trace_path = os.path.join(out_dir, "trace.jsonl") if out_dir else None
    if out_dir:
        os.makedirs(out_dir, exist_ok=True)
    tracer = JSONLTracer(path=trace_path)
    try:
        report = run_matrix(variants, config.channels, adapter, detector, tracer,
                            reset_between_variants=config.reset_between_variants)
    finally:
        tracer.close()
    report.limitations = limitations + report.limitations

    formats = (config.reporting or {}).get("formats", ["json", "markdown"])
    json_text = emit_json(report)
    md_text = emit_markdown(report) if "markdown" in formats else None
    html_text = emit_html(report) if (args.report_html or "html" in formats) else None

    if out_dir:
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

    if args.report_html:
        dirname = os.path.dirname(os.path.abspath(args.report_html))
        if dirname:
            os.makedirs(dirname, exist_ok=True)
        with open(args.report_html, "w", encoding="utf-8") as fh:
            fh.write(html_text)

    counts = report.counts_by_verdict
    status = {
        "run_id": report.run_id,
        "counts_by_verdict": counts,
        "overall_asr": report.overall_asr.display if report.overall_asr else "n/a (0/0)",
        "exit_code": _exit_code(counts, args.gate),
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
        errors = validate_catalog_file(path)
        if errors:
            total_errors += len(errors)
            for e in errors:
                print(f"- {e}")
        else:
            print(f"ok: {path}")
    print(f"{len(files)} file(s), {total_errors} error(s)", file=sys.stderr)
    return EXIT_OK if not total_errors else EXIT_ERROR


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="mcp_attack",
        description=f"Multi-step memory/tool attack harness v{ATTACK_ENGINE_VERSION} (schema {ATTACK_SCHEMA_VERSION})",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    pr = sub.add_parser("run", help="run an attack matrix against a configured target")
    pr.add_argument("--config", required=True, help="run config JSON (target + channels + catalog_paths)")
    pr.add_argument("--catalog", action="append", help="catalog file/dir (repeatable); overrides config.catalog_paths")
    pr.add_argument("--audit", help="an mcp_audit report JSON; filters/prioritizes the catalog by matched rule_ids")
    pr.add_argument("--audit-mode", choices=["filter", "prioritize"], default=None)
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
    pr.set_defaults(func=cmd_run)

    pl = sub.add_parser("list-catalog", help="print the loaded catalog's variant inventory")
    pl.add_argument("--catalog", action="append", required=True, help="catalog file/dir (repeatable)")
    pl.add_argument("--rule-id", help="only show variants tagged with this rule_id")
    pl.add_argument("--taxonomy", help="only show variants tagged with this owasp_amg_category")
    pl.set_defaults(func=cmd_list_catalog)

    pv = sub.add_parser("validate-catalog", help="validate one or more catalog files/dirs")
    pv.add_argument("paths", nargs="+")
    pv.set_defaults(func=cmd_validate_catalog)

    return parser


def main(argv: Optional[List[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
