"""JSON / JSONL / Markdown emitters and downstream feeders (TZ §16).

Both human-readable formats are generated from the same validated document
model, so they cannot contradict each other.  Untrusted fragments (definition
text, tool results, log lines) are escaped for Markdown and never rendered as
HTML; nothing external is loaded.
"""
from __future__ import annotations

import json
import re
from typing import Any, Dict, Iterable, List

from ..models import AuditDocument, ClaimStatus, ControlOutcome, Operation, Severity, StageObservation

_MD_ESCAPE = re.compile(r"([\\`*_{}\[\]()#+!|<>])")


def esc(text: Any, limit: int = 300) -> str:
    """Escape untrusted text for a Markdown table/list cell: no HTML, no links, no line breaks."""
    s = "" if text is None else str(text)
    s = s.replace("\r", " ").replace("\n", " ⏎ ")
    s = _MD_ESCAPE.sub(r"\\\1", s)
    if len(s) > limit:
        s = s[:limit] + "…"
    return s


def build_downstream(doc: AuditDocument) -> Dict[str, Any]:
    """P2 receives facts and uncertainties; later phases receive references to controls and
    preconditions.  Statuses are never upgraded here."""
    tools = doc.all_tools()
    ind = doc.summary.get("capability_indicators") or {}
    rows: List[Dict[str, Any]] = []

    def tm(row_id: str, title: str, state: str, refs: Any, status: str, preconditions: Iterable[str] = ()) -> None:
        rows.append({"id": row_id, "title": title, "state": state, "refs": refs, "claim_status": status,
                     "preconditions": list(preconditions),
                     "note": "fact/uncertainty for threat modelling; downstream must not rename a hypothesis into a confirmed result"})

    for key, row in (("arbitrary_code_execution", ("TM-EXEC", "Arbitrary code execution")),
                     ("write_access", ("TM-WRITE", "Data modification capability")),
                     ("full_project_access", ("TM-FULL", "Unbounded filesystem scope"))):
        i = ind.get(key) or {}
        tm(row[0], row[1], "present" if i.get("present") else "absent", i.get("tools"), i.get("status", "unknown"))
    tm("TM-EXFIL", "External channel", "present" if any(t.egress for t in tools) else "absent",
       [t.qualified_name for t in tools if t.egress], "hypothesis")
    poison = [f.finding_id for f in doc.definition_findings]
    tm("TM-POISON", "Definition-plane signals", "signals" if poison else "none", poison, "hypothesis")
    tri = doc.trifecta or {}
    tm("TM-TRIFECTA", "Lethal trifecta indicator", tri.get("state", "unknown"), tri.get("legs_present"),
       {"capability_combination": "hypothesis", "static_path_supported": "static_supported",
        "runtime_path_observed": "runtime_supported", "control_violation_observed": "runtime_supported"}.get(tri.get("state"), "unknown"))
    tm("TM-SHADOW", "Cross-server shadowing precondition", "present" if doc.collisions else "absent", doc.collisions,
       "static_supported" if doc.collisions else "contradicted")
    for r in doc.control_results:
        if r.control_outcome == ControlOutcome.FAIL:
            tm(f"TM-{r.rule_id}", f"Violated control {r.rule_id}", "fail", r.finding_refs,
               "runtime_supported" if r.method and r.method.value in ("observation", "controlled_validation") else "static_supported",
               preconditions=[str(v) for v in r.conditions.values()])
    corpus: List[Dict[str, Any]] = []
    if poison:
        corpus.append({"campaign": "C4-*", "name": "tool poisoning", "reason": "definition-plane signals (hypotheses)", "refs": poison})
    if any(f.code == "AUTHORIZATION_STEERING" for f in doc.findings):
        corpus.append({"campaign": "C4-IDOR", "name": "broken access control via tool params", "reason": "authorization steering signal + AUTH-02 result",
                       "refs": [r.rule_id for r in doc.control_results if r.rule_id == "AUTH-02"]})
    if (ind.get("arbitrary_code_execution") or {}).get("present"):
        corpus.append({"campaign": "C4-EXEC", "name": "command execution abuse", "reason": "EXEC capability present"})
    mem_fail = [r.rule_id for r in doc.control_results if r.rule_id.startswith("MEM-") and r.control_outcome == ControlOutcome.FAIL]
    if mem_fail or tri.get("capability_combination"):
        corpus.append({"campaign": "C2-*", "name": "memory / context poisoning", "reason": f"memory controls failed: {mem_fail}" if mem_fail else "trifecta capability combination",
                       "refs": mem_fail})
    return {"P2_matrix": rows, "P3_corpus": corpus, "P8_baseline_keys": sorted(doc.hash_baseline.keys()),
            "P2_uncertainties": [c.claim_id for c in doc.claims if c.claim_status in (ClaimStatus.HYPOTHESIS, ClaimStatus.INCONCLUSIVE)]}


def emit_json(doc: AuditDocument, indent: int = 2) -> str:
    doc.downstream = build_downstream(doc)
    return json.dumps(doc.to_dict(), indent=indent, ensure_ascii=False, sort_keys=False)


def emit_jsonl(doc: AuditDocument) -> str:
    """Streaming export: one line per finding / evidence / claim / control result (same statuses as the JSON)."""
    lines: List[str] = []
    header = {"record": "run", "run_id": doc.run_id, "schema_version": doc.to_dict()["schema_version"], "target": doc.target}
    lines.append(json.dumps(header, ensure_ascii=False))
    for e in doc.evidence:
        lines.append(json.dumps({"record": "evidence", **e.to_dict()}, ensure_ascii=False))
    for c in doc.claims:
        lines.append(json.dumps({"record": "claim", **c.to_dict()}, ensure_ascii=False))
    for r in doc.control_results:
        lines.append(json.dumps({"record": "control_result", **r.to_dict()}, ensure_ascii=False))
    for f in doc.findings:
        lines.append(json.dumps({"record": "finding", **f.to_dict()}, ensure_ascii=False))
    return "\n".join(lines) + "\n"


# --------------------------------------------------------------------------- #
# Markdown
# --------------------------------------------------------------------------- #

def _sev_label(f) -> str:
    if f.is_confirmed and f.severity:
        return f"{f.severity.value} (подтверждено: {f.verification_status.value})"
    return f"потенциально {f.effective_severity.value} (гипотеза: {f.verification_status.value})"


def emit_markdown(doc: AuditDocument) -> str:
    d = doc.to_dict()
    v = doc.verdict or {}
    s = doc.summary or {}
    L: List[str] = []
    L.append(f"# Отчёт аудита безопасности агентной системы — {esc(doc.target.get('id') or 'цель не задана')}")
    L.append("")
    # 1. target, version, environment, mode, limits
    L.append("## 1. Цель, версии, среда, режим и пределы оценки")
    L.append("")
    L.append(f"- Цель: **{esc(doc.target.get('id'))}**, сборка: `{esc(doc.target.get('build_ref') or 'не задана')}`, среда: {esc(doc.target.get('environment') or 'не задана')}")
    L.append(f"- Режим: `{doc.mode.value}`, профиль источников: `{doc.access_profile.value}`, run: `{doc.run_id}`")
    L.append(f"- Версии: схема отчёта {d['schema_version']}, движок {d['meta'].get('engine_version')}, правила {d['meta'].get('ruleset_version')}")
    L.append(f"- Runtime-проверки выполнялись: **{'да' if doc.runtime_validation_performed else 'нет'}**")
    L.append(f"- Состояние оценки: **{esc(v.get('assessment_state'))}**; вывод по безопасности: **{esc(v.get('security_conclusion'))}**")
    if v.get("assessment_state") != "complete_for_scope":
        L.append(f"- ⚠ **Покрытие неполное**: не разрешённые контроли — {esc(', '.join(v.get('unresolved_controls') or []) or 'нет')}; "
                 f"недоступные адаптеры — {esc(', '.join(v.get('missing_adapters') or []) or 'нет')}")
    conf = v.get("confidence") or {}
    L.append(f"- Уверенность: {esc(conf.get('level'))} — {esc(conf.get('explanation'))}")
    L.append("")
    # 2. key confirmed conclusions
    L.append("## 2. Наиболее важные подтверждённые выводы и приоритеты")
    L.append("")
    confirmed = sorted([f for f in doc.findings if f.is_confirmed and f.plane not in ("definition", "context")],
                       key=lambda f: (-f.effective_severity.rank, f.remediation_priority.value if f.remediation_priority else "P9"))
    if confirmed:
        L.append("| Приоритет | Серьёзность | Правило | Finding | Статус подтверждения |")
        L.append("|---|---|---|---|---|")
        for f in confirmed[:20]:
            L.append(f"| {f.remediation_priority.value if f.remediation_priority else '-'} | {f.effective_severity.value} | {f.rule_id} | "
                     f"{esc(f.title, 120)} (`{f.finding_id}`) | {f.verification_status.value} |")
    else:
        L.append("Подтверждённых нарушений нет в проверенной области. Это не означает отсутствие дефектов вне покрытия.")
    hyps = [f for f in doc.findings if not f.is_confirmed]
    if hyps:
        L.append("")
        L.append(f"Гипотезы, требующие разбора: {len(hyps)} (перечислены в разделе 5 отдельно от подтверждённых).")
    L.append("")
    # 3. coverage
    L.append("## 3. Покрытие, недоступные источники и незавершённые проверки")
    L.append("")
    L.append("| Адаптер | Вид | Версия | Статус | Причины |")
    L.append("|---|---|---|---|---|")
    for a in doc.adapters:
        L.append(f"| {esc(a.adapter_id)} | {a.kind} | {a.adapter_version} | **{a.status}** | {esc('; '.join(a.reasons), 200)} |")
    L.append("")
    L.append("| Метрика | Значение | Знаменатель | Неизвестно | Ограничение |")
    L.append("|---|---|---|---|---|")
    for c in doc.coverage:
        L.append(f"| {c.metric} | {esc(c.display)} | {esc(c.denominator_source, 80)} | {c.unknown} | {esc(c.limitation, 120)} |")
    ne = [r for r in doc.control_results if r.control_outcome in (ControlOutcome.NOT_EVALUATED, ControlOutcome.INCONCLUSIVE)]
    if ne:
        L.append("")
        L.append("Незавершённые контроли:")
        for r in ne:
            L.append(f"- `{r.rule_id}`: {r.control_outcome.value} — {esc(r.interpretation, 200)}")
    L.append("")
    # 4. components & boundaries
    L.append("## 4. Карта компонентов и границ доверия")
    L.append("")
    if doc.components:
        L.append("| Компонент | Тип | Роль | Источники инвентаря | Состояние знания |")
        L.append("|---|---|---|---|---|")
        for c in doc.components:
            L.append(f"| `{esc(c.component_id)}` | {c.type} | {esc(c.role)} | {esc(', '.join(c.inventory_sources))} | {c.knowledge_state.value} |")
    if doc.boundaries:
        L.append("")
        L.append("| Граница | Откуда → куда | Правило | Точка исполнения | Наблюдение |")
        L.append("|---|---|---|---|---|")
        for b in doc.boundaries:
            L.append(f"| `{esc(b.boundary_id)}` | {esc(b.from_ref)} → {esc(b.to_ref)} | {esc(b.rule, 100)} | {esc(b.enforcement_point)} | {b.observation_status} |")
    if doc.edges:
        L.append("")
        L.append(f"Рёбер графа: {len(doc.edges)}; состояния: " + esc(", ".join(f"{e.kind}:{e.state.value}" for e in doc.edges[:12])))
    corr = s.get("correlation") or {}
    if corr.get("chains"):
        L.append("")
        L.append("| Цепочка | Состояние | Условия |")
        L.append("|---|---|---|")
        for ch in corr["chains"]:
            L.append(f"| {esc(ch.get('title') or ch.get('chain_id'), 100)} | **{ch.get('state')}** | {esc('; '.join(ch.get('conditions') or []), 150)} |")
    tri = doc.trifecta or {}
    L.append("")
    L.append(f"Индикатор LETHAL_TRIFECTA: **{esc(tri.get('state'))}** — {esc(tri.get('explanation'), 300)}")
    L.append("")
    L.append("### Инвентарь")
    L.append("")
    L.append("| Сервер | Источник каталога | Handshake | Инструмент | Класс | Операции | Риск возможности | Основание |")
    L.append("|---|---|---|---|---|---|---|---|")
    for srv in doc.servers:
        hs = srv.handshake
        hs_txt = ("выполнен, " + hs.completeness) if hs.performed else "не выполнялся"
        for t in srv.tools:
            L.append(f"| {esc(srv.name)} | {hs.source} | {hs_txt} | `{esc(t.name)}` | {t.classification.value} | {esc(','.join(t.operations))} | "
                     f"{t.capability_risk.value} | {t.classification_basis}/{t.knowledge_state.value} |")
    rec = [r for r in doc.inventory_reconciliation if r.get("kind") in ("inventory_mismatch", "contract_mismatch")]
    if rec:
        L.append("")
        L.append("Расхождения инвентаря и контрактов:")
        for r in rec:
            L.append(f"- {esc(r.get('detail'), 400)}")
            if r.get("ratio_note"):
                L.append(f"  - {esc(r['ratio_note'], 300)}")
    L.append("")
    # 5. findings
    L.append("## 5. Findings: основания и критерии закрытия")
    L.append("")
    L.append("### 5.1 Подтверждённые (static_supported / runtime_supported)")
    L.append("")
    if not confirmed:
        L.append("Нет.")
    for f in confirmed:
        _finding_block(L, f)
    L.append("")
    L.append("### 5.2 Гипотезы и сигналы (требуют разбора; не являются подтверждённым нарушением)")
    L.append("")
    if not hyps:
        L.append("Нет.")
    for f in sorted(hyps, key=lambda f: -f.effective_severity.rank):
        _finding_block(L, f, short=True)
    L.append("")
    # 6. memory stages
    L.append("## 6. Результаты памяти по стадиям W/R/C/B")
    L.append("")
    if doc.memory_cases:
        L.append("| Случай | Запись | Субъект | W | R | C | B | Вывод |")
        L.append("|---|---|---|---|---|---|---|---|")
        for c in doc.memory_cases:
            st = c.get("stages", {})
            L.append(f"| {esc(c.get('case_id'))} | {esc(c.get('memory_id'))} | {esc(c.get('subject'))} | {st.get('W')} | {st.get('R')} | {st.get('C')} | {st.get('B')} | {esc(c.get('conclusion'), 150)} |")
        for c in doc.memory_cases:
            for lim in c.get("limitations") or []:
                L.append(f"- {esc(c.get('case_id'))}: {esc(lim, 250)}")
    else:
        L.append("Стадийные наблюдения памяти не проводились (нет случаев/трасс): W/R/C/B = not_evaluated.")
    mem = [r for r in doc.control_results if r.rule_id.startswith("MEM-")]
    if mem:
        L.append("")
        L.append("| Правило | Применимость | Выполнение | Исход | Интерпретация |")
        L.append("|---|---|---|---|---|")
        for r in mem:
            L.append(f"| {r.rule_id} | {r.applicability.value} | {r.execution_status.value} | **{r.control_outcome.value}** | {esc(r.interpretation, 200)} |")
    L.append("")
    # 7. auth & egress
    L.append("## 7. Результаты авторизации и исходящих эффектов")
    L.append("")
    L.append("| Правило | Применимость | Выполнение | Исход | Границы | Интерпретация |")
    L.append("|---|---|---|---|---|---|")
    for r in doc.control_results:
        if r.rule_id.startswith(("AUTH-", "INFRA-", "TOOL-", "EGRESS-", "INV-")):
            L.append(f"| {r.rule_id} | {r.applicability.value} | {r.execution_status.value} | **{r.control_outcome.value}** | "
                     f"{esc(', '.join(r.evaluated_boundary_refs))} | {esc(r.interpretation, 200)} |")
    if doc.tests:
        L.append("")
        L.append("| Контрольный случай | Инструмент | Ожидание | Выполнение | Класс ошибки | Эффект | Исход |")
        L.append("|---|---|---|---|---|---|---|")
        for t in doc.tests:
            L.append(f"| {esc(t.id)} | {esc(t.tool)} | {t.expected} | {t.execution_status.value} | {t.error_class.value} | "
                     f"{esc((t.observed_effect or {}).get('details'), 120)} | **{t.control_outcome.value}** |")
    L.append("")
    # 8. drift
    L.append("## 8. Изменения относительно совместимого baseline")
    L.append("")
    if doc.drift:
        dr = doc.drift
        L.append(f"- Сопоставимость: {dr.get('compatibility', {}).get('comparable')}; ограничения: {esc('; '.join(dr.get('compatibility', {}).get('reasons') or []), 300)}")
        L.append(f"- Итог: {esc(dr.get('summary'))}; состояние согласования: **{esc(dr.get('approval_state'))}**")
        for c in dr.get("changes") or []:
            L.append(f"- {c.get('kind')}: `{esc(c.get('key'))}` — {esc(c.get('interpretation') or c.get('detail') or '', 200)} ({esc(c.get('approval_state', ''))})")
    else:
        L.append("Baseline не задан; сравнение не выполнялось.")
    L.append("")
    # 9. remediation plan
    L.append("## 9. План исправлений, повторная оценка и ограничения")
    L.append("")
    if confirmed:
        L.append("| Приоритет | Finding | Исправление | Критерий закрытия |")
        L.append("|---|---|---|---|")
        for f in confirmed:
            L.append(f"| {f.remediation_priority.value if f.remediation_priority else '-'} | `{f.finding_id}` | {esc(f.remediation, 200)} | {esc(f.closure_criterion, 200)} |")
    L.append("")
    L.append("Ограничения оценки:")
    for lim in (v.get("limitations") or [])[:40]:
        L.append(f"- {esc(lim, 300)}")
    L.append("")
    # 10. evidence registry
    L.append("## 10. Реестр свидетельств и версий правил")
    L.append("")
    L.append(f"Свидетельств: {len(doc.evidence)}; утверждений: {len(doc.claims)}; правила: {d['meta'].get('ruleset_version')}")
    L.append("")
    L.append("| ID | Источник | Метод | Локатор | Ограничения |")
    L.append("|---|---|---|---|---|")
    for e in doc.evidence[:200]:
        loc = ", ".join(f"{k}={v}" for k, v in e.locator.items() if v not in (None, ""))
        L.append(f"| `{e.evidence_id}` | {e.source_type.value} | {e.method.value} | {esc(loc, 120)} | {esc('; '.join(e.limitations), 120)} |")
    if len(doc.evidence) > 200:
        L.append(f"| … | ещё {len(doc.evidence) - 200} | | | |")
    L.append("")
    L.append("Версии правил, применённые в этом запуске:")
    seen = set()
    for r in doc.control_results:
        if r.rule_id not in seen:
            seen.add(r.rule_id)
            L.append(f"- {r.rule_id} v{r.rule_version}")
    L.append("")
    L.append("*Аудит — диагностика, а не защита. Статические выводы описывают дефекты кода/конфигурации, а не наблюдаемое влияние на работающую модель. "
             "Недоверенные фрагменты экранированы; внешнее содержимое не подгружается.*")
    return "\n".join(L) + "\n"


def _finding_block(L: List[str], f, short: bool = False) -> None:
    loc = "/".join(x for x in (f.server, f.tool) if x)
    L.append(f"- **[{_sev_label(f)}] {f.rule_id} `{f.finding_id}` `{f.code}`**{(' (' + esc(loc) + ')') if loc else ''} — {esc(f.title, 150)}")
    L.append(f"  - {esc(f.description, 400)}")
    if not short:
        if f.root_cause:
            L.append(f"  - Корневая причина: {esc(f.root_cause, 200)}")
        if f.preconditions:
            L.append(f"  - Предпосылки: {esc('; '.join(f.preconditions), 200)}")
        L.append(f"  - Наблюдаемый эффект: {esc(f.observed_effect or 'не наблюдался')}; возможный эффект: {esc(f.potential_effect or '-')}")
        L.append(f"  - Основания: claims {esc(', '.join(f.claim_refs) or '-')}; evidence {esc(', '.join(f.evidence_refs) or '-')}")
        if f.memory_stages:
            L.append("  - Стадии памяти: " + ", ".join(f"{k}={v.value if isinstance(v, StageObservation) else v}" for k, v in f.memory_stages.items()))
        L.append(f"  - Исправление: {esc(f.remediation, 250)} Критерий закрытия: {esc(f.closure_criterion, 250)}")
    if f.limitations:
        L.append(f"  - Ограничения: {esc('; '.join(f.limitations[:4]), 300)}")
