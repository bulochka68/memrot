"""Garak-inspired, self-contained HTML dashboard: one static file, no build
step, no external network dependency at view time -- open it directly in a
browser. Built from the exact same ``RunReport.to_dict()`` as ``emit_json``/
``emit_markdown`` (see ``emitter.py``), so all three outputs can never
disagree with each other.

Severity coloring is a simple, undocumented-corpus-free stand-in for garak's
DEFCON/Z-score grading: garak calibrates a Z-score against a reference set
of previously-tested models, which this project has no equivalent corpus
for. Instead, a group's raw ASR ratio is mapped directly to a color band --
higher ASR (more attacks got through) reads as more alarming (red), lower
ASR reads as safer (green). This is a coarser signal than garak's calibrated
score, but requires no reference corpus and is honest about not having one.
"""
from __future__ import annotations

import html
import json
import time
from typing import Dict, Optional

from ..models import GroupMetric, RunReport

_SEVERITY_BANDS = (
    (0.66, "#dc2626", "critical"),   # >=66% ASR
    (0.33, "#ea580c", "high"),        # >=33%
    (0.0, "#ca8a04", "moderate"),      # >0%
)


def _esc(value: object) -> str:
    return html.escape("" if value is None else str(value), quote=True)


def _severity(ratio: Optional[float]) -> tuple:
    """Returns (color, label) for a GroupMetric ratio; None (n/a, 0/0) and
    exactly 0.0 (attempted, never confirmed) are both treated as the safe
    band but are visually distinguished via the metric's own display text."""
    if ratio is None:
        return "#6b7280", "n/a"
    if ratio == 0.0:
        return "#16a34a", "clean"
    for threshold, color, label in _SEVERITY_BANDS:
        if ratio >= threshold:
            return color, label
    return "#16a34a", "clean"


def _metric_row(label: str, metric: GroupMetric) -> str:
    color, severity = _severity(metric.ratio)
    pct = round((metric.ratio or 0.0) * 100, 1)
    return (
        "<tr>"
        f'<td class="key-cell">{_esc(label)}</td>'
        f'<td class="bar-cell"><div class="bar-track"><div class="bar-fill" '
        f'style="width:{pct}%;background:{color}"></div></div></td>'
        f'<td class="value-cell" style="color:{color}">{_esc(metric.display)}</td>'
        f'<td class="severity-cell"><span class="chip" style="border-color:{color};color:{color}">{severity}</span></td>'
        "</tr>"
    )


def _metric_table(groups: Dict[str, GroupMetric], empty_note: str) -> str:
    if not groups:
        return f'<p class="muted">{_esc(empty_note)}</p>'
    rows = "".join(_metric_row(key, metric) for key, metric in sorted(groups.items()))
    return (
        '<table class="metric-table"><thead><tr><th>Key</th><th>ASR</th><th></th><th>Severity</th></tr></thead>'
        f"<tbody>{rows}</tbody></table>"
    )


def _kpi_card(label: str, value: str, color: str = "#e5e7eb") -> str:
    return (
        '<div class="kpi-card">'
        f'<div class="kpi-value" style="color:{color}">{_esc(value)}</div>'
        f'<div class="kpi-label">{_esc(label)}</div>'
        "</div>"
    )


def _verdict_chip(verdict: str, count: int) -> str:
    colors = {"CONFIRMED": "#dc2626", "CLEAN": "#16a34a", "INVALID": "#6b7280",
             "ERROR": "#9333ea", "NOT_EVALUATED": "#6b7280"}
    color = colors.get(verdict, "#6b7280")
    return (f'<span class="chip" style="border-color:{color};color:{color}">'
           f"{_esc(verdict)}: {count}</span>")


def _result_row(r: dict) -> str:
    verdict = r.get("verdict", "")
    colors = {"CONFIRMED": "#dc2626", "CLEAN": "#16a34a", "INVALID": "#6b7280",
             "ERROR": "#9333ea", "NOT_EVALUATED": "#6b7280"}
    color = colors.get(verdict, "#6b7280")
    rule_ids = ", ".join(r.get("rule_ids") or []) or "—"
    return (
        '<tr class="result-row" '
        f'data-search="{_esc((r.get("variant_id","") + " " + rule_ids + " " + str(r.get("owasp_amg_category","")) + " " + str(r.get("path_state","")) + " " + str(r.get("mutation_technique",""))).lower())}">'
        f'<td>{_esc(r.get("variant_id"))}</td>'
        f'<td><span class="chip" style="border-color:{color};color:{color}">{_esc(verdict)}</span></td>'
        f'<td>{_esc(r.get("path_state") or "—")}</td>'
        f'<td>{_esc(r.get("owasp_amg_category") or "—")}</td>'
        f'<td>{_esc(rule_ids)}</td>'
        f'<td>{_esc(r.get("mutation_technique") or "—")}</td>'
        f'<td>{_esc(r.get("framing"))}</td>'
        f'<td>{_esc(r.get("payload"))}</td>'
        f'<td>{_esc(r.get("propagation"))}</td>'
        "</tr>"
    )


_STYLE = """
:root { color-scheme: dark; }
* { box-sizing: border-box; }
body { margin: 0; font-family: -apple-system, "Segoe UI", Roboto, sans-serif;
      background: #0f1115; color: #e5e7eb; }
.wrap { max-width: 1100px; margin: 0 auto; padding: 32px 20px 64px; }
h1 { font-size: 22px; margin: 0 0 4px; }
h2 { font-size: 16px; margin: 36px 0 12px; color: #f3f4f6; border-bottom: 1px solid #262b36; padding-bottom: 6px; }
.meta { color: #9ca3af; font-size: 13px; margin-bottom: 24px; }
.muted { color: #6b7280; font-size: 13px; }
.kpi-row { display: flex; gap: 12px; flex-wrap: wrap; margin: 20px 0; }
.kpi-card { background: #161a22; border: 1px solid #262b36; border-radius: 10px;
           padding: 16px 20px; min-width: 140px; }
.kpi-value { font-size: 28px; font-weight: 700; }
.kpi-label { font-size: 12px; color: #9ca3af; margin-top: 4px; text-transform: uppercase; letter-spacing: .04em; }
.chip { display: inline-block; border: 1px solid; border-radius: 999px; padding: 2px 10px;
       font-size: 11px; font-weight: 600; margin: 2px 4px 2px 0; }
table.metric-table, table.results-table { width: 100%; border-collapse: collapse; font-size: 13px; }
table.metric-table td, table.metric-table th,
table.results-table td, table.results-table th { padding: 7px 10px; border-bottom: 1px solid #1f2430; text-align: left; }
table.metric-table th, table.results-table th { color: #9ca3af; font-weight: 600; font-size: 11px;
                                              text-transform: uppercase; letter-spacing: .03em; }
.key-cell { white-space: nowrap; max-width: 260px; overflow: hidden; text-overflow: ellipsis; }
.bar-cell { width: 40%; }
.bar-track { background: #1f2430; border-radius: 4px; height: 8px; overflow: hidden; }
.bar-fill { height: 100%; border-radius: 4px; }
.value-cell { white-space: nowrap; font-variant-numeric: tabular-nums; }
.severity-cell { white-space: nowrap; }
.axis-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(260px, 1fr)); gap: 20px; }
input#filter { width: 100%; padding: 8px 12px; margin-bottom: 10px; background: #161a22;
             border: 1px solid #262b36; border-radius: 8px; color: #e5e7eb; font-size: 13px; }
.limitations li { margin-bottom: 6px; color: #d1d5db; font-size: 13px; }
footer { margin-top: 40px; color: #6b7280; font-size: 12px; }
@media (prefers-color-scheme: light) {
  :root { color-scheme: light; }
  body { background: #f7f8fa; color: #1f2430; }
  .kpi-card { background: #ffffff; border-color: #e5e7eb; }
  h2 { border-color: #e5e7eb; color: #111827; }
  table.metric-table td, table.metric-table th,
  table.results-table td, table.results-table th { border-color: #e5e7eb; }
  .bar-track { background: #e5e7eb; }
  input#filter { background: #ffffff; border-color: #e5e7eb; color: #1f2430; }
}
"""

_SCRIPT = """
document.getElementById('filter').addEventListener('input', function (ev) {
  var q = ev.target.value.toLowerCase();
  document.querySelectorAll('.result-row').forEach(function (row) {
    row.style.display = row.dataset.search.indexOf(q) === -1 ? 'none' : '';
  });
});
"""


def _json_script_safe(data: dict) -> str:
    """json.dumps does not escape '</', so attacker-controlled content (a
    variant id, a probe/canary string) containing a literal '</script>' could
    otherwise break out of the embedding <script> tag. Standard mitigation:
    escape the closing-tag sequence inside the JSON text itself."""
    return json.dumps(data, ensure_ascii=False).replace("</", "<\\/")


def emit_html(report: RunReport) -> str:
    data = report.to_dict()
    overall = report.overall_asr
    overall_color, overall_label = _severity(overall.ratio if overall else None)
    overall_display = overall.display if overall else "n/a (0/0)"

    kpis = [
        _kpi_card("Overall ASR", overall_display, overall_color),
        _kpi_card("Variants run", str(len(report.results))),
        _kpi_card("Channels", str(len(report.channels))),
    ]
    verdict_chips = "".join(_verdict_chip(v, c) for v, c in sorted(report.counts_by_verdict.items()))

    axis_sections = "".join(
        f'<div><h3 style="font-size:13px;color:#9ca3af;margin:0 0 8px;text-transform:capitalize">{_esc(axis)}</h3>'
        f'{_metric_table(groups, "no data for this axis")}</div>'
        for axis, groups in report.asr_by_axis.items() if groups
    )

    limitations_html = ""
    if report.limitations:
        items = "".join(f"<li>{_esc(l)}</li>" for l in report.limitations)
        limitations_html = f'<h2>Limitations</h2><ul class="limitations">{items}</ul>'

    results_rows = "".join(_result_row(r) for r in data["results"])

    started = time.strftime("%Y-%m-%d %H:%M:%S UTC", time.gmtime(report.started_at))
    finished = (time.strftime("%Y-%m-%d %H:%M:%S UTC", time.gmtime(report.finished_at))
               if report.finished_at else "—")

    return f"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>memrot report: {_esc(report.run_id)}</title>
<style>{_STYLE}</style>
</head>
<body>
<div class="wrap">
  <h1>Attack run report: {_esc(report.run_id)}</h1>
  <div class="meta">Target: <code>{_esc(report.target_id)}</code> &middot; Started {started} &middot; Finished {finished}</div>
  <div class="kpi-row">{"".join(kpis)}</div>
  <div>{verdict_chips}</div>

  <h2>ASR by taxonomy category (OWASP Agent Memory Guard)</h2>
  {_metric_table(report.asr_by_taxonomy_category, "no owasp_amg_category tags in this run")}

  <h2>ASR by technique category (delivery / obfuscation)</h2>
  {_metric_table(report.asr_by_technique_category, "no technique_category tags in this run")}

  <h2>ASR by source (curated vs synthesized)</h2>
  {_metric_table(report.asr_by_source, "no source tags in this run")}

  <h2>ASR by mutation technique</h2>
  {_metric_table(report.asr_by_mutation_technique, "no mutated variants in this run")}

  <h2>ASR by threat model</h2>
  {_metric_table(report.asr_by_threat_model, "no results in this run")}

  <h2>ASR by rule id</h2>
  {_metric_table(report.asr_by_rule_id, "no rule_ids tagged in this run")}

  <h2>ASR by diversity axis</h2>
  <div class="axis-grid">{axis_sections}</div>

  {limitations_html}

  <h2>Per-variant results ({len(report.results)})</h2>
  <input id="filter" type="text" placeholder="Filter by variant id, rule id, category, or mutation technique...">
  <table class="results-table">
    <thead><tr><th>Variant</th><th>Verdict</th><th>Path state</th><th>Category</th><th>Rule IDs</th>
    <th>Mutation</th><th>Framing</th><th>Payload</th><th>Propagation</th></tr></thead>
    <tbody>{results_rows}</tbody>
  </table>

  <footer>
    memrot v1 &middot; trace: {_esc(report.trace_path or "not recorded")}
    &middot; generated {time.strftime("%Y-%m-%d %H:%M:%S UTC", time.gmtime())}
  </footer>
</div>
<script type="application/json" id="report-data">{_json_script_safe(data)}</script>
<script>{_SCRIPT}</script>
</body>
</html>
"""
