"""Command-line interface for the MCP audit subsystem.

Examples:
    python -m mcp_audit audit config.json --json out.json --md report.md
    python -m mcp_audit audit config.json --live --mcp-scan
    python -m mcp_audit audit config.json --mode active --sandbox      # inside P0 only
    python -m mcp_audit baseline config.json -o baseline.json
    python -m mcp_audit drift config.json --baseline baseline.json
"""
from __future__ import annotations

import argparse
import json
import sys
from typing import List, Optional

from .models import Mode, Risk
from .orchestrator import Orchestrator, audit_from_config
from .discovery import load_config_file, parse_snapshot
from .reporting import emit_json, emit_markdown, save_baseline

_EXIT_BY_RISK = {"LOW": 0, "MEDIUM": 0, "HIGH": 1, "CRITICAL": 2}


def _add_common(p: argparse.ArgumentParser) -> None:
    p.add_argument("config", help="path to the MCP config file (mcpServers / servers / bare / list)")
    p.add_argument("--live", action="store_true", help="perform a live MCP handshake (spawns servers)")
    p.add_argument("--snapshot", help="tools snapshot JSON to use instead of a live handshake")
    p.add_argument("--context-root", help="directory to scan for agent context files (CLAUDE.md, ...)")
    p.add_argument("--timeout", type=float, default=20.0)
    p.add_argument("--cwd", help="working directory for spawned stdio servers")


def cmd_audit(args: argparse.Namespace) -> int:
    mode = Mode(args.mode)
    doc = audit_from_config(
        args.config, mode=mode, live=args.live, snapshot_path=args.snapshot,
        context_root=args.context_root, use_mcp_scan=args.mcp_scan, sandbox=args.sandbox,
        timeout=args.timeout, cwd=args.cwd,
    )
    out = emit_json(doc)
    if args.json:
        with open(args.json, "w", encoding="utf-8") as fh:
            fh.write(out)
    if args.md:
        with open(args.md, "w", encoding="utf-8") as fh:
            fh.write(emit_markdown(doc))
    if args.baseline_out:
        save_baseline(doc, args.baseline_out)
    if not args.json or args.stdout:
        print(out)
    else:
        v = doc.verdict
        print(f"overall_risk={doc.summary['overall_risk']} "
              f"exec={v['arbitrary_code_execution']} trifecta={v['lethal_trifecta']} "
              f"findings={len(doc.security_findings)} -> {args.json}", file=sys.stderr)
    if args.fail_on_risk:
        return _EXIT_BY_RISK.get(doc.summary["overall_risk"], 0)
    return 0


def cmd_baseline(args: argparse.Namespace) -> int:
    doc = audit_from_config(args.config, mode=Mode.PASSIVE, live=args.live,
                            snapshot_path=args.snapshot, timeout=args.timeout, cwd=args.cwd)
    baseline = save_baseline(doc, args.output)
    print(f"baseline written to {args.output}: {len(baseline['hash_baseline'])} definitions", file=sys.stderr)
    return 0


def cmd_drift(args: argparse.Namespace) -> int:
    doc = audit_from_config(args.config, mode=Mode.DRIFT, live=args.live,
                            snapshot_path=args.snapshot, baseline_path=args.baseline,
                            timeout=args.timeout, cwd=args.cwd)
    print(json.dumps(doc.drift, indent=2, ensure_ascii=False))
    if args.fail_on_drift and not doc.drift.get("clean"):
        return 3
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="mcp_audit", description="MCP agent audit subsystem (pipeline P1)")
    sub = parser.add_subparsers(dest="command", required=True)

    pa = sub.add_parser("audit", help="run the full audit")
    _add_common(pa)
    pa.add_argument("--mode", choices=[m.value for m in Mode], default="passive")
    pa.add_argument("--sandbox", action="store_true", help="acknowledge sandbox for active mode (P0 only)")
    pa.add_argument("--mcp-scan", action="store_true", help="also run Invariant Labs mcp-scan if present")
    pa.add_argument("--json", help="write audit JSON to this path")
    pa.add_argument("--md", help="write a Markdown report to this path")
    pa.add_argument("--baseline-out", help="also write a drift baseline to this path")
    pa.add_argument("--stdout", action="store_true", help="print JSON even when --json is set")
    pa.add_argument("--fail-on-risk", action="store_true", help="exit non-zero on HIGH/CRITICAL")
    pa.set_defaults(func=cmd_audit)

    pb = sub.add_parser("baseline", help="write a drift baseline")
    _add_common(pb)
    pb.add_argument("-o", "--output", required=True)
    pb.set_defaults(func=cmd_baseline)

    pd = sub.add_parser("drift", help="compare against a baseline (P8)")
    _add_common(pd)
    pd.add_argument("--baseline", required=True)
    pd.add_argument("--fail-on-drift", action="store_true")
    pd.set_defaults(func=cmd_drift)
    return parser


def main(argv: Optional[List[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
