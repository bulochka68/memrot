# Адаптеры источников и форматы входных данных (v2.0)

Все адаптеры возвращают ядру нормализованные свидетельства и объявляют
`adapter_version`, поддерживаемые возможности и явные причины `unsupported`
(ТЗ §5.3). Неизвестные поля источника сохраняются как расширения.
Отсутствующий или неисправный адаптер даёт статус `unavailable` / `partial` /
`stale`, а зависящие от него контроли — `NOT_EVALUATED`.

| kind | Что читает | Что не предполагает |
|---|---|---|
| `mcp_inventory` | конфиг MCP-клиента (`configured`), снимок прошлого handshake (`snapshot`), живой handshake (`live_advertised`, только в live-режимах), контекстные файлы агента | что отсутствие инструмента для одной роли доказывает его отсутствие для другой; что конфиг — это handshake |
| `source_snapshot` | дерево исходников (объявления инструментов по стратегии из профиля: `decorator`, `registry_dict`, `list_literal`, `json_file`; проверка потоков профиля регулярными выражениями, в том числе по `strategy: "regex_only"` для языков без AST) или заранее извлечённый файл фактов | что имя функции определяет её побочные эффекты; код не исполняется; вычисляемое во время импорта объявление возвращается как `unknown`, а не угадывается |
| `policy_snapshot` | ожидаемая политика доступа и памяти (`access-policy`) | что описание политики доказывает её исполнение |
| `memory_event_snapshot` | нормализованные записи памяти и события write / retrieve / context_include / revoke | что Redis / MongoDB / векторная БД сами изолируют пользователей |
| `trace` | JSONL-события с субъектом, компонентом, причинными связями и версиями | что текст ответа сервиса достоверен |
| `deployment` | compose YAML или JSON-снимок сервисов: публикация портов, имена переменных окружения, признаки аутентификации хранилищ | что опубликованный порт доступен из интернета; значения окружения не читаются |
| `control_fixtures` | зарегистрированные контрольные случаи и декларация изоляции фикстуры | что запуск по догадке об имени инструмента допустим |

## Манифест цели (`schema_version: "2.0"`)

```json
{
  "schema_version": "2.0",
  "target": {"id": "genai-invest-stand", "build_ref": "<commit>", "environment": "local-compose-stand"},
  "inspection": {"access_profile": "white_box", "mode": "offline", "profile_ref": "../profiles/genai_invest_stand.json",
                 "required_controls": ["MEM-01", "MEM-02", "AUTH-01", "AUTH-02"]},
  "adapters": [
    {"id": "mcp-config", "kind": "mcp_inventory", "binding": {"path": "config.json", "live": false, "capture": {"method": "…"}}},
    {"id": "source", "kind": "source_snapshot", "binding": {"path": "source_facts.json"}},
    {"id": "policy", "kind": "policy_snapshot", "binding": {"path": "policy.json"}},
    {"id": "deployment", "kind": "deployment", "binding": {"path": "deployment.json"}}
  ],
  "reporting": {"formats": ["json", "markdown"], "evidence_policy_ref": "redacted-evidence-v1"},
  "reproducibility": {"model_versions": {}, "prompt_versions": {}}
}
```

Секреты в манифест не включаются: поля `password` / `token` / `secret` /
`api_key` с непустым значением отклоняются. Живой адаптер получает учётные данные
через имя привязки: `binding.credential_binding = "NAME"` читается из
переменной окружения `MCP_AUDIT_CRED_NAME` и никогда не попадает в отчёт.
YAML принимается при наличии PyYAML; JSON работает без зависимостей.
Простой конфиг MCP-клиента оборачивается в манифест автоматически (режим offline).

## Профиль системы (`profiles/*.json`)

Профиль хранит имена конкретной системы, чтобы правила оставались общими
(ТЗ §19.1, §22.1): компоненты и их роли (`user_session_handler`,
`background_worker`, `policy_publisher`, `resource_service`, …), хранилища памяти
с типами (`audience`, `authority`, `trusted_publishers`), маршрутизацию имён
инструментов (`tool_routing.namespace`: `flat` | `qualified` | `unknown`),
эталонный инвентарь, побочные эффекты других компонентов, цепочки для корреляции
и спецификацию `source_facts`:

| Группа | Ключевые атрибуты | Кто потребляет |
|---|---|---|
| `tool_declarations` | `component`, `path`, `decorator`, `kind` | инвентарь `source_defined`, INV-01, TOOL-02 |
| `flows` | `kind` ∈ publish / scope_decision / context_include / memory_read / memory_write / derivation / trust_elevation / transmit / store_access / revocation_check / retention / identity_binding / security_mode / data_flow / control_flow; `path`, `symbol`, `patterns`, `negate_patterns` + атрибуты вида | MEM-*, AUTH-01/03/06, INFRA-01, TOOL-04, EGRESS-01, граф |
| `auth_transitions` | `input_principal → executing_component → operation → resource → next_component`, `policy_decision` (enforced / not_enforced / conditional / n/a), `default_condition`, `client_can_weaken`, `delegation`, `subject_bound`, `conditions` | AUTH-02, AUTH-03, AUTH-05 |
| `token_validation` | `component`, `scheme`, `checks.{signature,issuer,audience,expiry,algorithm}` с `pattern`, `found_means`, `absent_means` | AUTH-04 |
| `background_jobs` | `carries_identity`, `idempotent`, `checks_policy_revision`, `effects` | MEM-09, компоненты |
| `break_points` | `kind` (truncation / filter / authz / egress_block), `durable_control` | корреляция |

Каждый элемент с `path` / `symbol` / `patterns` проверяется адаптером: символ
найден и все шаблоны совпали → `static_supported`; символ есть, шаблон нет (или
запрещённый шаблон присутствует) → `contradicted`; файл/символ недоступен →
`unknown`. Свидетельство содержит путь, символ, диапазон строк, digest и
ограниченный фрагмент.

Извлечение переносимого файла фактов:
`python -m mcp_audit source-snapshot --root <checkout> --profile profiles/x.json --commit <sha> -o facts.json`.

## Политика (`schema: "access-policy"`)

Разделы: `principals`, `access_rules` (`subject`, `operation`, `resource`,
`condition`, `enforcement`), `boundaries`, `memory_policy` (`memory_types` с
`audience`, `authority`, `trusted_publishers`, `allowed_writers`,
`review_required`, `retention`, `derived`; `scope_decision_authority`;
`allowed_sharing`; `revocation`), `authentication` (схема и ожидаемые issuer /
audience по сервисам), `mandatory_server_checks`, `service_rights`
(`component → store → [read, write, publish]`), `network`
(`storage_publication`), `egress` (`allowed_destinations` с категориями),
`authorized_tools` (инвентарь `policy_authorized`), `tool_approval`.
Если политика совместного доступа не определена, аудитор показывает поток
данных, но не угадывает нарушение (EGRESS-01 → `INCONCLUSIVE`).

## События памяти (`schema: "memory-events"`)

```json
{"schema": "memory-events", "store_ref": "mongo", "captured_at": 1788600000.0,
 "field_map": {"memory_id": "id", "subject_ref": "user_id", "read_audience_ref": "audience"},
 "coverage": {"write": true, "retrieve": true, "context_include": false, "behavior": false},
 "records": [{"id": "policy-1", "memory_type": "shared_policy", "audience": "shared", "writer": "session-finalizer", "review_state": null}],
 "events": [{"event_id": "e1", "run_id": "r1", "trace_id": "t1", "parent_event_refs": [], "component": "session-finalizer",
             "ts": 1788600001.0, "config_version": "c1", "principal": "client1001",
             "memory": {"memory_id": "policy-1", "operation": "write", "proposed_scope": "global", "proposed_by": "llm",
                        "resolved_scope": "shared", "writer": "session-finalizer", "policy_decision": "accepted_proposed"}}]}
```

Записи нормализуются к полям ТЗ §8.3; неизвестные значения остаются `null` и
перечисляются в `unknown_fields`; `trusted` / `verified` / `owner` внутри
содержимого сохраняются отдельно как `self_asserted`. `coverage` определяет,
может ли отсутствие события считаться `not_observed`; без coverage стадия —
`unknown`.

## Трасса (`*.jsonl`)

Первая строка может нести `{"_coverage": {...}}`. Обязательные поля события:
`event_id`, `run_id`, `trace_id`, `component`, `ts`, `principal`
(+ `parent_event_refs`, `config_version`). Блоки: `memory` (операция, области,
writer, решение политики, `included_in_context`, `context_role`), `tool`
(`qualified_id`, `definition_digest`, `resource`, `access_decision`,
`result_ref`), `flow` (`from`, `to`, `kind` — наблюдённый переход графа),
`observation` (`effect_id`, `observed`), `job` (`job_id`, `status`, `memory_ids`).
Качество наблюдения (пропущенные поля, несвязанные родители) записывается в
`meta.trace_quality`.

## Контрольные фикстуры (`schema: "control-fixtures"`)

```json
{"schema": "control-fixtures",
 "isolation": {"data": "synthetic", "network": "none", "permissions": "unprivileged", "attested_by": "pytest fixture"},
 "roots": {"filesystem": "/tmp/fixture-root"},
 "cases": [{"id": "FS-TRAVERSAL", "server": "filesystem", "tool": "write_file", "rule_id": "AUTH-02", "boundary_ref": "fs-root",
            "arguments": {"path": "{root}/../{canary}-outside.txt", "content": "{canary}"}, "expected": "denied",
            "expected_invariant": "a write outside the allowed root is refused and leaves no file",
            "effect_check": {"kind": "file_absent", "path": "{root}/../{canary}-outside.txt"}}],
 "memory_cases": [{"case_id": "MC-1", "memory_id": "policy-1", "subject": "client1002", "prepared_by": "fixture_admin", "effect_ref": "EFF-1"}]}
```

Плейсхолдеры: `{canary}`, `{sinkhole}`, `{root}`. Виды наблюдения эффекта:
`file_exists`, `file_absent`, `response_contains`, `response_not_contains`,
`sink_received`, `none` (без наблюдения нарушение не заявляется →
`INCONCLUSIVE`). Случай выполняется только если аргументы согласуются с
объявленной схемой инструмента; иначе `execution_status = skipped`,
`error_class = schema_error | unknown_tool`, `control_outcome = INCONCLUSIVE`.
`destructive: true` выполняется только с `--allow-destructive`.

## Снимок deployment (`schema: "deployment-snapshot"` или compose YAML)

Для каждого сервиса: `image` / `build`, `ports`, `environment` (только имена
ключей), `command`, `depends_on`. Из них выводятся `host_published`,
`loopback_only`, `storage_kind`, `storage_auth` (`true` при явных признаках,
иначе `null` с basis «authentication not shown in this configuration»).
