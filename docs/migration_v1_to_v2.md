# Миграция с audit v1.0 / v1.1 на agent-security-audit v2.0

Документ описывает, как старые артефакты читаются новым движком и что при этом
**не** делается (ТЗ §18). Reader старых форматов сохранён; v2 выпускается
отдельным сериализатором.

## Версии, которые различаются

| Что версионируется | v1 | v2 | Где задано |
|---|---|---|---|
| Схема отчёта | `audit` 1.0 / 1.1 | `agent-security-audit` 2.0 | `mcp_audit.AUDIT_SCHEMA_VERSION`, `schemas/agent-security-audit-2.0.schema.json` |
| Движок | 1.1.0 | 2.0.0 | `mcp_audit.__version__` |
| Каталог правил | — | 2.0.0 | `mcp_audit.RULESET_VERSION`, `python -m mcp_audit rules` |
| Документация | v1 | 2.0 | `mcp_audit.DOC_VERSION`, `docs/audit_subsystem_architecture.md` |
| Канонизация хэша определения | неявная («1») | `c2` | `static_analysis.hasher.CANONICALIZATION_VERSION` |
| Baseline | 1.1 | 2.0 | `reporting.baseline.BASELINE_VERSION` |

## Правила импорта (`python -m mcp_audit migrate old.json -o new.json`)

1. Старый документ валидируется **по своей** версии (`schema == "audit"`, `version ∈ {1.0, 1.1}`, обязательные ключи). Неизвестная версия отклоняется, а не угадывается.
2. Исходные значения (`verdict`, `summary`, `mode`, число `tests`) сохраняются в `import_history.original`; им не приписываются новые свидетельства — единственное свидетельство импорта имеет `source_type = imported`.
3. `declared` переносится как заявление источника; `effective` — как вывод, требующий политики или наблюдения (`effective_access.policy_expected` c basis «legacy 'effective' block re-read as expectation»).
4. `verified = true` у инструмента становится runtime-подтверждением только при наличии относящегося к нему валидного результата в `tests`; иначе остаётся в `provenance.verified_import` как история с пометкой «NOT promoted».
5. Старый `PASS` читается с учётом ожидаемого эффекта: в v1 эффект не наблюдался независимо от текста ответа, поэтому новый исход — `INCONCLUSIVE`. `BLOCKED` при ожидании `BLOCKED` — `PASS` с ограничением «object-level semantics unknown».
6. `tests = []` означает, что проверки не выполнялись; это не список пройденных проверок (`import_history.interpretation.tests`).
7. Handshake **не** восстанавливается как выполненный из `source = config` + `ok = true`: `handshake.performed = false`, `ok = null`.
8. `full_project_access`, `arbitrary_code_execution`, `rug_pull` пересчитываются по новым определениям (индикаторы возможностей, drift с `approval_state`); прежняя трактовка остаётся в `import_history.interpretation`.
9. Числовая `confidence` (0.6, `0.6 + 0.4 × verified_ratio`) и строка `basis = "effective+verified"` отбрасываются: они не были калиброванной вероятностью и не были машинно проверяемыми ссылками.
10. Мигрированный документ получает `assessment_state = partial` и ограничение «no control rules were evaluated»: правила каталога по импортированному артефакту не оцениваются, потому что в нём нет источников (source/policy/trace).

## Сравнение со старым baseline

`drift` со старым baseline (версия 1.x) выполняется в ограниченном режиме:
`compatibility.limited = true`, причина — «legacy baseline; comparison limited to
definition hashes and names». Так как версия канонизации изменилась, различия
хэшей классифицируются как `comparison_inconclusive`, а не как изменение цели.
Для полноценного сравнения нужен baseline v2 (`python -m mcp_audit baseline …`).

## Что изменилось для потребителей JSON

| v1 поле | v2 эквивалент |
|---|---|
| `servers[]` | `inventory.servers[]` (+ `inventory_sources`, `field_sources`, `capture`, `handshake.performed`) |
| `tools[].classification` | сохранено как первичный класс; добавлены `operations`, `side_effects`, `classification_basis`, `knowledge_state`, `capability_risk` |
| `tools[].effective_access` | `policy_expected` / `inferred` / `observed` с `enforcement = unknown` |
| `tools[].verified` | удалено; см. `claims[]` со статусом `runtime_supported` и `tests[]` |
| `definition_analysis.findings` | `definition_analysis.finding_refs` → единый список `findings[]` (одна корневая причина — один устойчивый `finding_id`) |
| `security_findings` | `findings[]` с `plane ≠ definition` |
| `summary.overall_risk` | нет единой шкалы: `summary.max_capability_risk`, `findings_by_severity`, `control_results` |
| `verdict.confidence` (число) | `verdict.confidence = {level, explanation}` |
| `verdict.basis` (строка) | `verdict.basis = [claim ids]` |
| `verdict.lethal_trifecta` (bool) | `trifecta.state` ∈ capability_combination / static_path_supported / runtime_path_observed / control_violation_observed / unknown |
| `drift.rug_pull` | `drift.changes[].kind = definition_changed` + `approval_state` |
| `tests[].result` PASS/BLOCKED/FAIL | `tests[].execution_status` × `error_class` × `control_outcome` |

Совместимость не повышает доверие: если исторический отчёт не позволяет
установить смысл проверки, это самостоятельное ограничение качества данных,
и оно записывается в `import_history.limitations`.
