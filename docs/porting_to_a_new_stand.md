# Перенос аудита на другой стенд

Движок `mcp_audit` системно-независим: 28 контрольных правил не содержат имён
конкретного стенда (коллекций, инструментов, компонентов). Всё системно-специфичное
живёт в **профиле**, поэтому перенос аудита на новый стенд — это написание
входных данных, а не изменение кода.

Трогать `mcp_audit/` при переносе не нужно. Если правило не выражается через
профиль — это повод обсудить новое правило, а не хардкодить имя стенда.

## Что пишется руками, а что генерируется

| Файл | Кто создаёт |
|---|---|
| `profiles/<стенд>.json` | **руками** — компоненты, память, границы, спецификация извлечения фактов |
| `<стенд>.policy.json` | **руками** — ожидаемая политика доступа и памяти |
| `<стенд>.manifest.json` | **руками** — цель, режим, привязка адаптеров |
| `<стенд>.source_facts.json` | генерируется: `python -m mcp_audit source-snapshot` |
| `<стенд>.deployment.json` | адаптер читает `docker-compose.yml` напрямую |
| MCP-конфиг клиента | берётся у стенда как есть |
| baseline | генерируется: `python -m mcp_audit baseline` |
| правила | уже написаны, системно-независимы |

Готовые образцы: `profiles/rest_native_agent.json` (56 строк, агент без MCP —
берите как шаблон), `profiles/genai_invest_stand.json` (1104 строки, полный
пример), `examples/genai_invest_stand.*` (манифест, политика, снимки, отчёт).

## Сколько правил даёт каждый источник

Посчитано по `required_sources` каталога правил (`python -m mcp_audit rules`):

```
+ MCP-конфиг       5/28   EGRESS-01, INV-02, TOOL-02, TOOL-03, TOOL-05
+ source_facts    21/28   AUTH-01…06, INV-01, MEM-01…07, MEM-09, TOOL-04
+ policy          24/28   INFRA-01, MEM-08, MEM-10
+ deployment      25/28   INFRA-02          ← потолок офлайн-режима
+ memory_events   25/28   —  (углубляют уже применимые правила до runtime_supported)
+ trace           25/28   —  (то же)
+ fixtures        27/28   EGRESS-02, INFRA-03
+ baseline        28/28   TOOL-01
```

Главный вывод: прыжок **5 → 21** даёт секция `source_facts` профиля. Это и есть
основная работа при переносе. `trace` и `memory_event_snapshot` новых правил не
открывают, но переводят статусы находок из `static_supported` в
`runtime_supported` и заполняют стадии памяти W/R/C/B.

---

## Шаг 1. Профиль — `profiles/<стенд>.json`

### Обязательный минимум

```json
{
  "profile_id": "мой-стенд",
  "profile_version": "1.0.0",
  "description": "…",
  "components": [
    {"id": "assistant-api", "type": "rest_service", "name": "…",
     "role": "user_session_handler", "source_paths": ["app/api.py"]}
  ]
}
```

Типы компонентов, встречающиеся в готовых профилях: `agent`, `orchestrator`,
`rest_service`, `mcp_server`, `native_function`, `memory_store`,
`policy_publisher`, `background_job`, `identity_provider`, `external_provider`.

### Секции по мере необходимости

| Секция | Зачем | Влияет на |
|---|---|---|
| `servers` | алиасы «имя MCP-сервера → `component.id`» | инвентарь, материализация native-инструментов |
| `memory_stores`, `memory_field_map` | типы памяти: `audience`, `authority`, `derived`, `trusted_publishers`; маппинг полей записи | MEM-* |
| `boundaries` | границы доверия; попадают в граф как `ASSUMED` (границы из политики — как `KNOWN`) | корреляция, `boundary_coverage` |
| `principals` | акторы и роли | AUTH-*, `identity_coverage` |
| `reference_inventory` | эталонный список инструментов по серверам | метрика `inventory_completeness` |
| `tool_routing` | как имена инструментов разрешаются в вызовы | TOOL-* |
| `side_effects`, `revocation`, `chains` | семантика поведения и значимые цепочки | TOOL-*, EGRESS-*, корреляция |
| `memory_cases` | кейсы памяти для наблюдения по событиям | стадии W/R/C/B |
| `source_facts` | **спецификация извлечения фактов из кода** | почти всё |

### `source_facts` — сердце профиля

Это не факты, а описание того, **как их найти и чем проверить**. Каждая запись —
утверждение о коде, которое движок обязан подтвердить или опровергнуть.

Группы: `tool_declarations`, `flows`, `auth_transitions`, `token_validation`,
`background_jobs`, `break_points`.

**Объявления инструментов** — AST-скан по декоратору:

```json
"tool_declarations": [
  {"component": "native-tools", "path": "app/tools.py", "decorator": "tool", "kind": "native"},
  {"component": "mcp-invest",   "path": "mcp-invest/server.py", "decorator": "mcp.tool", "kind": "mcp"}
]
```

**Поток** — символ плюс регулярные выражения по его телу:

```json
{"id": "R-note-write", "kind": "memory_write",
 "from": "assistant-api", "to": "vector-memory",
 "path": "app/memory.py", "symbol": "VectorMemory.write_note",
 "patterns": ["INSERT INTO notes", "source_refs"],
 "memory_type": "note", "audience": "user", "writer_principal": "assistant-api",
 "provenance_kept": true, "provenance_fields": ["source_refs"],
 "statement": "Запись заметки сохраняет ссылки на источник.",
 "rule_refs": ["MEM-05"],
 "limitations": ["права БД работающего deployment не проверены"]}
```

Значения `kind`, используемые правилами: `memory_write`, `memory_read`,
`context_include`, `publish`, `scope_decision`, `identity_binding`, `transmit`,
`store_access`, `derivation`, `retention`, `revocation_check`, `trust_elevation`,
`security_mode`, `data_flow`, `control_flow`.

**Переход авторизации** — кто, над каким ресурсом, где точка контроля:

```json
"auth_transitions": [
  {"id": "RT-doc", "input_principal": "end_user", "executing_component": "assistant-api",
   "operation": "READ", "resource": "document(doc_id)", "auth_scheme": "jwt",
   "boundary": "RB-doc", "enforcement_point": "assistant-api",
   "path": "app/api.py", "symbol": "get_document",
   "patterns": ["if doc\\[\"owner\"\\] != subject", "HTTPException\\(status_code=403"],
   "policy_decision": "enforced"}
]
```

**Проверка токена** — по одной регулярке на каждую проверку:

```json
"token_validation": [
  {"component": "assistant-api", "path": "app/api.py", "symbol": "current_principal", "scheme": "jwt",
   "checks": {"signature": {"pattern": "jwt\\.decode\\(", "found_means": true},
              "issuer":    {"pattern": "issuer=EXPECTED_ISSUER", "found_means": true},
              "audience":  {"pattern": "audience=EXPECTED_AUDIENCE", "found_means": true},
              "expiry":    {"pattern": "jwt\\.decode\\(", "found_means": true},
              "algorithm": {"pattern": "algorithms=\\[\"RS256\"\\]", "found_means": true}}}
]
```

### Как это проверяется

`extract_facts()` (`mcp_audit/adapters/source_snapshot.py`) для каждой записи:

1. находит файл, считает его `sha256`;
2. достаёт символ через AST вместе с номерами строк;
3. проверяет `patterns` и `negate_patterns` по телу символа;
4. выставляет статус:
   * `static_supported` — совпало,
   * `contradicted` — файл и символ есть, паттерн не совпал,
   * `unknown` — файла или символа нет;
5. формирует улику: локатор `{path, symbol, lines}`, дайджест тела, обрезанный фрагмент.

**Рукописное утверждение само по себе ничего не подтверждает.** Пишите паттерны
от реального кода и сразу прогоняйте `source-snapshot`: `contradicted` в отчёте
читается как «код противоречит заявленному», а не «автор ошибся в регулярке».

## Шаг 2. Политика — `<стенд>.policy.json`

```json
{"schema": "access-policy", "policy_id": "…", "version": "1.0.0", "owner": "…",
 "principals": [...], "access_rules": [...], "boundaries": [...],
 "memory_policy": {...}, "authentication": {...}}
```

Распознаваемые секции: `principals`, `access_rules`, `boundaries`,
`memory_policy`, `authentication`, `mandatory_server_checks`, `service_rights`,
`network`, `egress`, `tool_approval`, `authorized_tools`, `retention`,
`revocation`. Нераспознанные сохраняются в `extensions["x-policy"]`.

Без `memory_policy`, `access_rules` и `authentication` адаптер уходит в `partial`.

Политика — декларация ожиданий: `"declared expectations; not evidence of
enforcement"`. Она не доказывает, что правила действительно применяются.

## Шаг 3. Манифест — `<стенд>.manifest.json`

```json
{
  "schema_version": "2.0",
  "target": {"id": "мой-стенд", "build_ref": "<commit>", "environment": "…"},
  "inspection": {"access_profile": "white_box", "mode": "offline",
                 "profile_ref": "../profiles/мой-стенд.json"},
  "adapters": [
    {"id": "mcp-config", "kind": "mcp_inventory",   "binding": {"path": "мой.config.json", "live": false}},
    {"id": "source",     "kind": "source_snapshot", "binding": {"path": "мой.source_facts.json"}},
    {"id": "policy",     "kind": "policy_snapshot", "binding": {"path": "мой.policy.json"}},
    {"id": "deployment", "kind": "deployment",      "binding": {"path": "docker-compose.yml"}}
  ],
  "reporting": {"formats": ["json", "markdown"]},
  "reproducibility": {"model_versions": {}, "prompt_versions": {}}
}
```

* `schema_version` обязан быть `"2.0"` — иные версии не угадываются, загрузка падает.
* `build_ref` и `environment` подмешиваются в `scope` **каждой** улики: без них
  выводы не привязаны к версии системы.
* Относительные пути в `binding` резолвятся от каталога манифеста.
* Секреты запрещены: непустые строковые поля `password`, `secret`, `token`,
  `api_key`, `apikey`, `client_secret`, `authorization` отклоняют файл целиком.
  Учётные данные передаются именем привязки: `binding.credential_binding = "NAME"`
  → переменная окружения `MCP_AUDIT_CRED_NAME`.

Адаптер `deployment` принимает либо `docker-compose.yml` (нужен PyYAML), либо
JSON-снимок `{"services": {name: {"image", "ports", "environment", …}}}`.
Значения переменных окружения не сохраняются — только имена ключей.
Манифест в YAML тоже требует PyYAML; в JSON зависимостей нет.

Форматы всех входов адаптеров — в [`adapters_and_formats.md`](adapters_and_formats.md).

## Шаг 4. Прогон

```bash
# 1. извлечь факты из кода по профилю
python -m mcp_audit source-snapshot --profile profiles/мой-стенд.json \
    --root . --commit "$(git rev-parse HEAD)" -o examples/мой.source_facts.json

# 2. офлайн-аудит
python -m mcp_audit audit examples/мой.manifest.json \
    --json .audit/мой.json --md .audit/мой.md --gate

# 3. проверить структуру и ссылочную целостность отчёта
python -m mcp_audit validate .audit/мой.json
```

Коды возврата:

| Код | Когда |
|---|---|
| `0` | без `--gate` — всегда, если аудит не упал; с `--gate` — `complete_for_scope` и `no_violations_observed` |
| `1` | `--gate`: `security_conclusion == findings_present` |
| `2` | `--gate`: оценка неполная или вывод не `no_violations_observed`; `drift --fail-on-drift`: снимки несравнимы |
| `3` | `drift --fail-on-drift`: материальный дрейф |
| `4` | аудит завершился `failed`, ошибка загрузки входов, либо `--strict` и отчёт не прошёл валидацию |

## Шаг 5. Что смотреть в результате

1. **`plan.entries`** — какие правила `planned`, какие `not_evaluated` и каких
   источников им не хватает (`missing_sources`). Это карта пробелов.
2. **`adapters[].status`** — `unavailable` или `partial` означает, что источник
   не прочитался; причина в `reasons`.
3. **Статусы в `source_facts`** — `contradicted` и `unknown` показывают, где
   профиль разошёлся с кодом.
4. **`coverage`** — метрики с числителем, знаменателем и списком пробелов;
   неизвестный знаменатель даёт «не определено», а не 100 %.
5. **`verdict`** — `assessment_state` станет `complete_for_scope` только когда
   нет нерешённых контролей и все адаптеры доступны.

Отсутствующий источник никогда не превращается в зелёный вердикт: он виден в
плане, в покрытии и как `NOT_EVALUATED` на затронутых контролях.

## Шаг 6. Тест

Добавьте тест по образцу `tests/test_rest_native_profile.py` — там ровно этот
сценарий: второй профиль на тех же правилах, без изменения движка. Фикстуры
кладутся в `tests/fixtures/`.

## Типичные ошибки

| Симптом | Причина |
|---|---|
| правила массово `not_evaluated` | не привязан `source_snapshot`: в связке с одним лишь MCP-конфигом он открывает 16 правил, а 5 (MEM-10, AUTH-01, AUTH-03, AUTH-04, AUTH-05) без него не оцениваются ни при каком наборе остальных источников |
| поток в статусе `unknown` | неверный `path` или `symbol` не найден в файле |
| поток в статусе `contradicted` | паттерн не совпал: либо регулярка неточна, либо код действительно другой |
| `assessment_state: partial` при всех зелёных контролях | какой-то адаптер `partial`/`stale` или есть `unresolved_controls` |
| загрузка манифеста падает | `schema_version` не `"2.0"` либо в файле секретоподобное поле |
| профиль не найден | `profile_ref` резолвится от каталога манифеста; голый id ищется в `profiles/` |
| `inventory_completeness` = «не определено» | не задан `reference_inventory` в профиле и `authorized_tools` в политике |

## Смежные документы

* [`auditor.md`](auditor.md) — режимы, команды, формат отчёта
* [`adapters_and_formats.md`](adapters_and_formats.md) — форматы входов всех адаптеров
* [`rules_catalog.md`](rules_catalog.md) — что требует и что проверяет каждое из 28 правил
* [`audit_subsystem_architecture.md`](audit_subsystem_architecture.md) — архитектура подсистемы
* [`stand_selection.md`](stand_selection.md) — выбор второго стенда: ограничения движка и сравнение кандидатов
