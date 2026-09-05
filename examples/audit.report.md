# Отчёт аудита безопасности агентной системы — legacy-mcp-config

## 1. Цель, версии, среда, режим и пределы оценки

- Цель: **legacy-mcp-config**, сборка: `не задана`, среда: unknown
- Режим: `offline`, профиль источников: `grey_box`, run: `run-2425feb6f6e7`
- Версии: схема отчёта 2.0, движок 2.0.0, правила 2.0.0
- Runtime-проверки выполнялись: **нет**
- Состояние оценки: **partial**; вывод по безопасности: **undetermined**
- ⚠ **Покрытие неполное**: не разрешённые контроли — MEM-01, MEM-02, MEM-03, MEM-04, MEM-05, MEM-06, MEM-07, MEM-08, MEM-09, MEM-10, AUTH-01, AUTH-02, AUTH-03, AUTH-04, AUTH-05, AUTH-06, INFRA-01, INFRA-02, TOOL-01, TOOL-02, TOOL-04, TOOL-05, EGRESS-01, INV-01, INV-02; недоступные адаптеры — нет
- Уверенность: low — absence of findings is only as strong as the coverage; no runtime observation

## 2. Наиболее важные подтверждённые выводы и приоритеты

Подтверждённых нарушений нет в проверенной области. Это не означает отсутствие дефектов вне покрытия.

Гипотезы, требующие разбора: 2 (перечислены в разделе 5 отдельно от подтверждённых).

## 3. Покрытие, недоступные источники и незавершённые проверки

| Адаптер | Вид | Версия | Статус | Причины |
|---|---|---|---|---|
| mcp-config | mcp_inventory | 2.0.0 | **available** |  |

| Метрика | Значение | Знаменатель | Неизвестно | Ограничение |
|---|---|---|---|---|
| inventory_completeness | не определено | no reference inventory | 0 | no reference list; overall completeness unknown |
| component_coverage | 2/4 \(50.0%\) | components of manifest/profile/inventory | 0 | does not show the depth of evaluation per component |
| mandatory_control_coverage | 1/26 \(3.9%\) | required controls minus justified not-applicable | 25 | INCONCLUSIVE, NOT\_EVALUATED and unknown applicability stay in the denominator |
| mandatory_control_coverage_static | 1/26 \(3.9%\) | same as above | 0 | static support shows code/config facts, not runtime behaviour |
| mandatory_control_coverage_runtime | 0/26 \(0.0%\) | same as above | 0 | runtime support is bound to the observed principal, build and environment |
| identity_coverage | не определено | policy has no access\_rules | 0 | expected relations unknown |
| memory_stage_W | не определено | applicable memory cases | 0 | stages are never merged into one verified |
| memory_stage_R | не определено | applicable memory cases | 0 | stages are never merged into one verified |
| memory_stage_C | не определено | applicable memory cases | 0 | stages are never merged into one verified |
| memory_stage_B | не определено | applicable memory cases | 0 | stages are never merged into one verified |
| boundary_coverage | не определено | boundaries of the accepted model | 0 | an unreached backend is not counted as evaluated |
| execution_quality | не определено | control cases | 0 | errors are not excluded to make the report look complete |
| observation_quality | не определено | no trace | 0 | no runtime observation available |

Незавершённые контроли:
- `MEM-01`: NOT_EVALUATED — required source\(s\) not bound: \['source\_snapshot'\] \(memory topology unknown\)
- `MEM-02`: NOT_EVALUATED — required source\(s\) not bound: \['source\_snapshot'\] \(memory topology unknown\)
- `MEM-03`: NOT_EVALUATED — required source\(s\) not bound: \['source\_snapshot'\] \(memory topology unknown\)
- `MEM-04`: NOT_EVALUATED — required source\(s\) not bound: \['source\_snapshot'\] \(memory topology unknown\)
- `MEM-05`: NOT_EVALUATED — required source\(s\) not bound: \['source\_snapshot'\] \(memory topology unknown\)
- `MEM-06`: NOT_EVALUATED — required source\(s\) not bound: \['source\_snapshot'\] \(memory topology unknown\)
- `MEM-07`: NOT_EVALUATED — required source\(s\) not bound: \['source\_snapshot'\] \(memory topology unknown\)
- `MEM-08`: NOT_EVALUATED — required source\(s\) not bound: \['memory\_event\_snapshot'\] \(memory topology unknown\)
- `MEM-09`: NOT_EVALUATED — required source\(s\) not bound: \['source\_snapshot'\] \(memory topology unknown\)
- `MEM-10`: NOT_EVALUATED — required source\(s\) not bound: \['policy\_snapshot', 'source\_snapshot'\] \(memory topology unknown\)
- `AUTH-01`: NOT_EVALUATED — required source\(s\) not bound: \['source\_snapshot'\] \(authorization topology unknown\)
- `AUTH-02`: NOT_EVALUATED — required source\(s\) not bound: \['source\_snapshot'\] \(authorization topology unknown\)
- `AUTH-03`: NOT_EVALUATED — required source\(s\) not bound: \['source\_snapshot'\] \(authorization topology unknown\)
- `AUTH-04`: NOT_EVALUATED — required source\(s\) not bound: \['source\_snapshot'\] \(authorization topology unknown\)
- `AUTH-05`: NOT_EVALUATED — required source\(s\) not bound: \['source\_snapshot'\] \(authorization topology unknown\)
- `AUTH-06`: NOT_EVALUATED — required source\(s\) not bound: \['source\_snapshot'\] \(authorization topology unknown\)
- `INFRA-01`: NOT_EVALUATED — required source\(s\) not bound: \['deployment'\] \(no deployment snapshot or store-access facts\)
- `INFRA-02`: NOT_EVALUATED — required source\(s\) not bound: \['deployment'\] \(no deployment snapshot or store-access facts\)
- `TOOL-01`: NOT_EVALUATED — required source\(s\) not bound: \['baseline'\]
- `TOOL-02`: NOT_EVALUATED — only one definition source per tool; contracts cannot be compared
- `TOOL-04`: NOT_EVALUATED — required source\(s\) not bound: \['source\_snapshot'\]
- `TOOL-05`: INCONCLUSIVE — 2 text signal\(s\) recorded as hypotheses with fragment, rule and explanation; an imperative, Unicode or a link does not prove malicious intent - review required
- `EGRESS-01`: NOT_EVALUATED — egress-capable tools \['shell/execute\_command', 'fetch/fetch'\] without a declared transmit flow or egress policy
- `INV-01`: NOT_EVALUATED — required source\(s\) not bound: \['source\_snapshot'\]
- `INV-02`: NOT_EVALUATED — discovery not performed in this mode \(configured catalogue only\)

## 4. Карта компонентов и границ доверия

| Компонент | Тип | Роль | Источники инвентаря | Состояние знания |
|---|---|---|---|---|
| `server:filesystem` | mcp_server |  | configured, summary | known |
| `server:postgres` | mcp_server |  | configured, summary | known |
| `server:shell` | mcp_server |  | configured, summary | known |
| `server:fetch` | mcp_server |  | configured, summary | known |

Индикатор LETHAL_TRIFECTA: **capability\_combination** — Capability combination present: sensitive access, untrusted input and an external channel exist in the inventory. No connected path is established. A single tool holds all three legs: \['shell/execute\_command'\].

### Инвентарь

| Сервер | Источник каталога | Handshake | Инструмент | Класс | Операции | Риск возможности | Основание |
|---|---|---|---|---|---|---|---|
| filesystem | config | не выполнялся | `read\_file` | READ | READ | HIGH | definition/assumed |
| filesystem | config | не выполнялся | `write\_file` | WRITE | CREATE,UPDATE | HIGH | definition/assumed |
| filesystem | config | не выполнялся | `delete\_file` | DELETE | DELETE | CRITICAL | definition/assumed |
| postgres | config | не выполнялся | `query` | READ | READ | HIGH | definition/assumed |
| shell | config | не выполнялся | `execute\_command` | EXEC | EXECUTE,READ,CREATE,UPDATE,DELETE,TRANSMIT | CRITICAL | definition/assumed |
| fetch | config | не выполнялся | `fetch` | READ | READ,TRANSMIT | MEDIUM | definition/assumed |

## 5. Findings: основания и критерии закрытия

### 5.1 Подтверждённые (static_supported / runtime_supported)

Нет.

### 5.2 Гипотезы и сигналы (требуют разбора; не являются подтверждённым нарушением)

- **[потенциально HIGH (гипотеза: hypothesis)] TOOL-05 `F-aa404cad06` `UNCONSTRAINED_EXEC_PARAMETER`** (postgres/query) — Unconstrained execution parameter
  - query.sql is a free string with no enum/pattern - arbitrary execution surface
  - Ограничения: schema heuristic: a hypothesis about misuse potential, not an observed abuse
- **[потенциально HIGH (гипотеза: hypothesis)] TOOL-05 `F-44249b0e3b` `UNCONSTRAINED_EXEC_PARAMETER`** (shell/execute\_command) — Unconstrained execution parameter
  - execute\_command.command is a free string with no enum/pattern - arbitrary execution surface
  - Ограничения: schema heuristic: a hypothesis about misuse potential, not an observed abuse

## 6. Результаты памяти по стадиям W/R/C/B

Стадийные наблюдения памяти не проводились (нет случаев/трасс): W/R/C/B = not_evaluated.

| Правило | Применимость | Выполнение | Исход | Интерпретация |
|---|---|---|---|---|
| MEM-01 | unknown | skipped | **NOT_EVALUATED** | required source\(s\) not bound: \['source\_snapshot'\] \(memory topology unknown\) |
| MEM-02 | unknown | skipped | **NOT_EVALUATED** | required source\(s\) not bound: \['source\_snapshot'\] \(memory topology unknown\) |
| MEM-03 | unknown | skipped | **NOT_EVALUATED** | required source\(s\) not bound: \['source\_snapshot'\] \(memory topology unknown\) |
| MEM-04 | unknown | skipped | **NOT_EVALUATED** | required source\(s\) not bound: \['source\_snapshot'\] \(memory topology unknown\) |
| MEM-05 | unknown | skipped | **NOT_EVALUATED** | required source\(s\) not bound: \['source\_snapshot'\] \(memory topology unknown\) |
| MEM-06 | unknown | skipped | **NOT_EVALUATED** | required source\(s\) not bound: \['source\_snapshot'\] \(memory topology unknown\) |
| MEM-07 | unknown | skipped | **NOT_EVALUATED** | required source\(s\) not bound: \['source\_snapshot'\] \(memory topology unknown\) |
| MEM-08 | unknown | skipped | **NOT_EVALUATED** | required source\(s\) not bound: \['memory\_event\_snapshot'\] \(memory topology unknown\) |
| MEM-09 | unknown | skipped | **NOT_EVALUATED** | required source\(s\) not bound: \['source\_snapshot'\] \(memory topology unknown\) |
| MEM-10 | unknown | skipped | **NOT_EVALUATED** | required source\(s\) not bound: \['policy\_snapshot', 'source\_snapshot'\] \(memory topology unknown\) |

## 7. Результаты авторизации и исходящих эффектов

| Правило | Применимость | Выполнение | Исход | Границы | Интерпретация |
|---|---|---|---|---|---|
| AUTH-01 | unknown | skipped | **NOT_EVALUATED** |  | required source\(s\) not bound: \['source\_snapshot'\] \(authorization topology unknown\) |
| AUTH-02 | unknown | skipped | **NOT_EVALUATED** |  | required source\(s\) not bound: \['source\_snapshot'\] \(authorization topology unknown\) |
| AUTH-03 | unknown | skipped | **NOT_EVALUATED** |  | required source\(s\) not bound: \['source\_snapshot'\] \(authorization topology unknown\) |
| AUTH-04 | unknown | skipped | **NOT_EVALUATED** |  | required source\(s\) not bound: \['source\_snapshot'\] \(authorization topology unknown\) |
| AUTH-05 | unknown | skipped | **NOT_EVALUATED** |  | required source\(s\) not bound: \['source\_snapshot'\] \(authorization topology unknown\) |
| AUTH-06 | unknown | skipped | **NOT_EVALUATED** |  | required source\(s\) not bound: \['source\_snapshot'\] \(authorization topology unknown\) |
| INFRA-01 | unknown | skipped | **NOT_EVALUATED** |  | required source\(s\) not bound: \['deployment'\] \(no deployment snapshot or store-access facts\) |
| INFRA-02 | unknown | skipped | **NOT_EVALUATED** |  | required source\(s\) not bound: \['deployment'\] \(no deployment snapshot or store-access facts\) |
| INFRA-03 | not_applicable | skipped | **NOT_APPLICABLE** |  | no controlled validation in this mode |
| TOOL-01 | applicable | skipped | **NOT_EVALUATED** |  | required source\(s\) not bound: \['baseline'\] |
| TOOL-02 | applicable | skipped | **NOT_EVALUATED** |  | only one definition source per tool; contracts cannot be compared |
| TOOL-03 | applicable | completed | **PASS** |  | router namespace: unknown; 0 name collision\(s\) |
| TOOL-04 | applicable | skipped | **NOT_EVALUATED** |  | required source\(s\) not bound: \['source\_snapshot'\] |
| TOOL-05 | applicable | completed | **INCONCLUSIVE** |  | 2 text signal\(s\) recorded as hypotheses with fragment, rule and explanation; an imperative, Unicode or a link does not prove malicious intent - review required |
| EGRESS-01 | applicable | skipped | **NOT_EVALUATED** |  | egress-capable tools \['shell/execute\_command', 'fetch/fetch'\] without a declared transmit flow or egress policy |
| EGRESS-02 | not_applicable | skipped | **NOT_APPLICABLE** |  | no controlled validation in this mode |
| INV-01 | applicable | skipped | **NOT_EVALUATED** |  | required source\(s\) not bound: \['source\_snapshot'\] |
| INV-02 | applicable | skipped | **NOT_EVALUATED** |  | discovery not performed in this mode \(configured catalogue only\) |

## 8. Изменения относительно совместимого baseline

Baseline не задан; сравнение не выполнялось.

## 9. План исправлений, повторная оценка и ограничения


Ограничения оценки:
- legacy MCP config wrapped into a manifest: target identity, build and environment were not declared
- MEM-01: NOT\_EVALUATED \(required source\(s\) not bound: \['source\_snapshot'\] \(memory topology unknown\)\)
- MEM-02: NOT\_EVALUATED \(required source\(s\) not bound: \['source\_snapshot'\] \(memory topology unknown\)\)
- MEM-03: NOT\_EVALUATED \(required source\(s\) not bound: \['source\_snapshot'\] \(memory topology unknown\)\)
- MEM-04: NOT\_EVALUATED \(required source\(s\) not bound: \['source\_snapshot'\] \(memory topology unknown\)\)
- MEM-05: NOT\_EVALUATED \(required source\(s\) not bound: \['source\_snapshot'\] \(memory topology unknown\)\)
- MEM-06: NOT\_EVALUATED \(required source\(s\) not bound: \['source\_snapshot'\] \(memory topology unknown\)\)
- MEM-07: NOT\_EVALUATED \(required source\(s\) not bound: \['source\_snapshot'\] \(memory topology unknown\)\)
- MEM-08: NOT\_EVALUATED \(required source\(s\) not bound: \['memory\_event\_snapshot'\] \(memory topology unknown\)\)
- MEM-09: NOT\_EVALUATED \(required source\(s\) not bound: \['source\_snapshot'\] \(memory topology unknown\)\)
- MEM-10: NOT\_EVALUATED \(required source\(s\) not bound: \['policy\_snapshot', 'source\_snapshot'\] \(memory topology unknown\)\)
- AUTH-01: NOT\_EVALUATED \(required source\(s\) not bound: \['source\_snapshot'\] \(authorization topology unknown\)\)
- AUTH-02: NOT\_EVALUATED \(required source\(s\) not bound: \['source\_snapshot'\] \(authorization topology unknown\)\)
- AUTH-03: NOT\_EVALUATED \(required source\(s\) not bound: \['source\_snapshot'\] \(authorization topology unknown\)\)
- AUTH-04: NOT\_EVALUATED \(required source\(s\) not bound: \['source\_snapshot'\] \(authorization topology unknown\)\)
- AUTH-05: NOT\_EVALUATED \(required source\(s\) not bound: \['source\_snapshot'\] \(authorization topology unknown\)\)
- AUTH-06: NOT\_EVALUATED \(required source\(s\) not bound: \['source\_snapshot'\] \(authorization topology unknown\)\)
- INFRA-01: NOT\_EVALUATED \(required source\(s\) not bound: \['deployment'\] \(no deployment snapshot or store-access facts\)\)
- INFRA-02: NOT\_EVALUATED \(required source\(s\) not bound: \['deployment'\] \(no deployment snapshot or store-access facts\)\)
- TOOL-01: NOT\_EVALUATED \(required source\(s\) not bound: \['baseline'\]\)
- TOOL-02: NOT\_EVALUATED \(only one definition source per tool; contracts cannot be compared\)
- TOOL-04: NOT\_EVALUATED \(required source\(s\) not bound: \['source\_snapshot'\]\)
- TOOL-05: INCONCLUSIVE \(2 text signal\(s\) recorded as hypotheses with fragment, rule and explanation; an imperative, Unicode or a link does not prove malicious intent - review required\)
- EGRESS-01: NOT\_EVALUATED \(egress-capable tools \['shell/execute\_command', 'fetch/fetch'\] without a declared transmit flow or egress policy\)
- INV-01: NOT\_EVALUATED \(required source\(s\) not bound: \['source\_snapshot'\]\)
- INV-02: NOT\_EVALUATED \(discovery not performed in this mode \(configured catalogue only\)\)
- no runtime validation was performed: all supported claims are static \(config, definitions, source, policy\)

## 10. Реестр свидетельств и версий правил

Свидетельств: 11; утверждений: 10; правила: 2.0.0

| ID | Источник | Метод | Локатор | Ограничения |
|---|---|---|---|---|
| `E-66df17d0db` | config | parsing | path=examples/mcp\_config.example.json, kind=mcp\_config |  |
| `E-20078d8472` | definition | parsing | path=examples/mcp\_config.example.json, server=filesystem, inventory=configured | configured catalogue: what the client config lists, not what a server advertises |
| `E-8b492daf61` | definition | parsing | path=examples/mcp\_config.example.json, server=postgres, inventory=configured | configured catalogue: what the client config lists, not what a server advertises |
| `E-b70239a1a1` | definition | parsing | path=examples/mcp\_config.example.json, server=shell, inventory=configured | configured catalogue: what the client config lists, not what a server advertises |
| `E-122b8b2f68` | definition | parsing | path=examples/mcp\_config.example.json, server=fetch, inventory=configured | configured catalogue: what the client config lists, not what a server advertises |
| `E-a16498a508` | definition | parsing | server=filesystem, tool=read\_file, inventory=config | definition text is untrusted self-report |
| `E-8bb4c82d91` | definition | parsing | server=filesystem, tool=write\_file, inventory=config | definition text is untrusted self-report |
| `E-1a82047222` | definition | parsing | server=filesystem, tool=delete\_file, inventory=config | definition text is untrusted self-report |
| `E-9542dd7d34` | definition | parsing | server=postgres, tool=query, inventory=config | definition text is untrusted self-report |
| `E-5fb5b315a4` | definition | parsing | server=shell, tool=execute\_command, inventory=config | definition text is untrusted self-report |
| `E-0d1f868132` | definition | parsing | server=fetch, tool=fetch, inventory=config | definition text is untrusted self-report |

Версии правил, применённые в этом запуске:
- MEM-01 v2.0.0
- MEM-02 v2.0.0
- MEM-03 v2.0.0
- MEM-04 v2.0.0
- MEM-05 v2.0.0
- MEM-06 v2.0.0
- MEM-07 v2.0.0
- MEM-08 v2.0.0
- MEM-09 v2.0.0
- MEM-10 v2.0.0
- AUTH-01 v2.0.0
- AUTH-02 v2.0.0
- AUTH-03 v2.0.0
- AUTH-04 v2.0.0
- AUTH-05 v2.0.0
- AUTH-06 v2.0.0
- INFRA-01 v2.0.0
- INFRA-02 v2.0.0
- INFRA-03 v2.0.0
- TOOL-01 v2.0.0
- TOOL-02 v2.0.0
- TOOL-03 v2.0.0
- TOOL-04 v2.0.0
- TOOL-05 v2.0.0
- EGRESS-01 v2.0.0
- EGRESS-02 v2.0.0
- INV-01 v2.0.0
- INV-02 v2.0.0

*Аудит — диагностика, а не защита. Статические выводы описывают дефекты кода/конфигурации, а не наблюдаемое влияние на работающую модель. Недоверенные фрагменты экранированы; внешнее содержимое не подгружается.*
