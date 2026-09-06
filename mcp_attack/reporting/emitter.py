"""JSON / Markdown emitters, generated from the same RunReport so the two
formats can never contradict each other. Untrusted fragments (attack prompts,
target responses) are escaped for Markdown and never rendered as HTML."""
from __future__ import annotations

import json
import re
from typing import Any

from ..models import RunReport

_MD_ESCAPE = re.compile(r"([\\`*_{}\[\]()#+!|<>])")


def esc(text: Any, limit: int = 200) -> str:
    s = "" if text is None else str(text)
    s = s.replace("\r", " ").replace("\n", " / ")
    s = _MD_ESCAPE.sub(r"\\\1", s)
    if len(s) > limit:
        s = s[:limit] + "…"
    return s


def emit_json(report: RunReport, indent: int = 2) -> str:
    return json.dumps(report.to_dict(), indent=indent, ensure_ascii=False, sort_keys=False)


def emit_markdown(report: RunReport) -> str:
    L = []
    L.append(f"# Attack run report: {report.run_id}")
    L.append("")
    L.append(f"- Target: `{esc(report.target_id)}`")
    L.append(f"- Channels: {', '.join(esc(c.channel_id) for c in report.channels)}")
    L.append(f"- Verdict counts: {esc(dict(report.counts_by_verdict))}")
    if report.overall_asr:
        L.append(f"- **Overall ASR: {report.overall_asr.display}**")
    L.append("")

    L.append("## Per-variant verdicts")
    L.append("")
    L.append("| Variant | Verdict | Rule IDs | Framing | Payload | Layer | Propagation |")
    L.append("|---|---|---|---|---|---|---|")
    for r in report.results:
        L.append(f"| {esc(r.variant_id)} | **{r.verdict.value}** | {esc(', '.join(r.rule_ids) or '—')} | "
                 f"{esc(r.framing)} | {esc(r.payload)} | {esc(r.layer)} | {esc(r.propagation)} |")
    L.append("")

    L.append("## ASR by rule id")
    L.append("")
    L.append("| Rule ID | ASR |")
    L.append("|---|---|")
    for rule_id, metric in sorted(report.asr_by_rule_id.items()):
        L.append(f"| {esc(rule_id)} | {metric.display} |")
    L.append("")

    L.append("## ASR by taxonomy category (OWASP Agent Memory Guard)")
    L.append("")
    L.append("| Category | ASR |")
    L.append("|---|---|")
    for cat, metric in sorted(report.asr_by_taxonomy_category.items()):
        L.append(f"| {esc(cat)} | {metric.display} |")
    L.append("")

    L.append("## ASR by mutation technique")
    L.append("")
    L.append("| Technique | ASR |")
    L.append("|---|---|")
    for technique, metric in sorted(report.asr_by_mutation_technique.items()):
        L.append(f"| {esc(technique)} | {metric.display} |")
    L.append("")

    L.append("## ASR by threat model")
    L.append("")
    L.append("| Threat model | ASR |")
    L.append("|---|---|")
    for tm, metric in sorted(report.asr_by_threat_model.items()):
        L.append(f"| {esc(tm)} | {metric.display} |")
    L.append("")

    L.append("## ASR by diversity axis")
    L.append("")
    for axis, groups in report.asr_by_axis.items():
        if not groups:
            continue
        L.append(f"### {axis}")
        L.append("")
        L.append("| Value | ASR |")
        L.append("|---|---|")
        for value, metric in sorted(groups.items()):
            L.append(f"| {esc(value)} | {metric.display} |")
        L.append("")

    if report.limitations:
        L.append("## Limitations")
        L.append("")
        for lim in report.limitations:
            L.append(f"- {esc(lim, limit=500)}")
        L.append("")

    if report.trace_path:
        L.append(f"Full trace log: `{esc(report.trace_path)}`")
        L.append("")

    return "\n".join(L) + "\n"
