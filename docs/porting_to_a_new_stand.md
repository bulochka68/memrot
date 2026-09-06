# Перенос аудита на другой стенд

Движок `mcp_audit` системно-независим: 28 контрольных правил не содержат имён
конкретного стенда (коллекций, инструментов, компонентов). Всё системно-специфичное
живёт в **профиле**, поэтому перенос аудита на новый стенд — это написание
входных данных, а не изменение кода.

Трогать `mcp_audit/` при переносе не нужно. Если правило не выражается через
профиль — это повод обсудить новое правило, а не хардкодить имя стенда.

Проверено на чужой системе: [MemPalace](https://github.com/MemPalace/mempalace)
(45 инструментов в словаре `TOOLS`, свой доменный словарь, hub поверх HTTP с
общим bearer-токеном) подключён тремя файлами — `profiles/mempalace.json`,
`examples/mempalace.policy.json`, `examples/mempalace.manifest.json` — без единой
правки пакета; `git diff --stat mcp_audit/` после подключения пуст. Attack-сторона
того же стенда прикручена так же данными — `examples/mempalace.attack.config.json`
плюс оверлей `mcp_attack/catalog/prompts/domain/mempalace/` (см. [Шаг 7](#шаг-7-attack-сторона--прикрутить-mcp_attack-к-тому-же-стенду)).

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
пример), `profiles/mempalace.json` (чужая система: реестр-словарь вместо
декораторов, доменный лексикон, объявленные возможности),
`examples/genai_invest_stand.*` и `examples/mempalace.*` (манифест, политика,
снимки, отчёт).

**Первым делом — `lint-profile`.** Профиль проверяется до аудита:

```bash
python -m mcp_audit lint-profile profiles/<стенд>.json --root /путь/к/коду \
    --sources mcp_inventory,policy_snapshot,deployment
```

Он ловит ровно то, что иначе молча превращается в `unknown`: несуществующий
`path`, ненайденный `symbol`, невалидную регулярку, опечатку в `rule_refs`,
ссылку на необъявленный компонент или границу, незнакомую секцию профиля. И
печатает, **какие правила профиль вообще открывает** с этим набором источников.
Коды возврата: `0` чисто, `1` есть проблемы, `4` профиль не читается.

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

**Объявления инструментов** — способ извлечения задаётся полем `strategy`:

```json
"tool_declarations": [
  {"component": "native-tools", "path": "app/tools.py", "decorator": "tool", "kind": "native"},
  {"component": "mcp-invest",   "path": "mcp-invest/server.py", "decorator": "mcp.tool", "kind": "mcp"},
  {"component": "mcp-server",   "path": "mempalace/mcp_server.py", "kind": "mcp",
   "strategy": "registry_dict", "symbol": "TOOLS",
   "description_key": "description", "schema_key": "input_schema"}
]
```

| `strategy` | Форма объявления | Как читается |
|---|---|---|
| `decorator` (по умолчанию) | `@tool` / `@mcp.tool` над функцией | AST-скан; поведение прежних профилей не меняется |
| `registry_dict` | модульный словарь `{имя: {описание, схема, handler}}` | `symbol` находится в AST, значения читаются `ast.literal_eval` |
| `list_literal` | модульный список словарей-определений | то же, имя берётся из `name_key` |
| `json_file` | определения вынесены в JSON/YAML рядом с кодом | читается файл, фиксируется его `sha256`; `pointer` — путь внутри документа |

Ключи-настройки: `name_key` (`name`), `description_key` (`description`),
`schema_key` (`inputSchema` / `input_schema` / `schema` / `parameters`),
`annotations_key` (`annotations`), `capabilities_key` (`x_audit`).

Запись, значение которой собирается во время импорта (`"tool": build_def(...)`),
получает статус `unknown` с причиной, а не пропускается молча: аудитор не
угадывает то, что нельзя прочитать без выполнения кода. Если стенд сам
размечает свои инструменты, положите `x_audit` прямо в запись реестра — эти
объявления попадут в классификацию (см. «Объявленные возможности»).

**Языки без AST.** Символы ищутся только в Python. Для остальных языков
объявите `"strategy": "regex_only"` — факт привязывается к файлу и диапазону
строк (`"lines": [10, 40]`, по умолчанию весь файл):

```json
{"id": "R-digest", "kind": "transmit", "from": "web-ui", "to": "digest-provider",
 "path": "ui/client.ts", "strategy": "regex_only",
 "patterns": ["fetch\\(\"https://digest\\."]}
```

Попытка найти `symbol` в не-Python файле даёт `unknown` с явной причиной
(`language not supported: .ts`), а не безмолвный пропуск.

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

### Объявленные возможности — `capabilities`

Свойства инструмента разрешаются в порядке **declared > annotation > heuristic >
unknown**. Объявить их можно в трёх местах, и все три — данные:

* в MCP-конфиге, рядом с определением инструмента:

```json
{"name": "vault_traverse", "description": "…", "inputSchema": {…},
 "x_audit": {"operations": ["READ"], "egress": false, "sensitive_source": true}}
```

* в реестре самого стенда (`x_audit` внутри записи `registry_dict`/`json_file`);
* в профиле, если конфиг стенда трогать нельзя:

```json
"capabilities": {
  "mempalace/mempalace_reconnect": {"operations": ["UPDATE"], "egress": false},
  "mempalace/mempalace_event_wait": {"operations": ["READ"], "egress": false},
  "mempalace/*": {"untrusted_input": true},
  "vault_traverse": {"operations": ["READ"]}
}
```

Ключ — `сервер/инструмент`, `компонент/инструмент`, `сервер/*`, `*/инструмент`
или голое имя инструмента; более специфичный ключ перекрывает менее
специфичный, а профиль перекрывает конфиг и реестр.

Объявляемые свойства: `classification`, `operations` (`READ`, `CREATE`,
`UPDATE`, `DELETE`, `EXECUTE`, `PUBLISH`, `TRANSMIT`), `egress`, `destructive`,
`sensitive_source`, `untrusted_input`, `executing_principal`, `phase`,
`target_scope`.

Что при этом остаётся честным:

* `classification_basis` становится `declared`, а `provenance.classification` —
  `declared:profile` / `declared:config` / `declared:source`: отчёт всегда
  отличает «нам сказали» от «мы вывели из имени»;
* `knowledge_state` остаётся `assumed` — автор конфига не является уликой;
  `known` по-прежнему требует рукопожатия или кода;
* объявление, противоречащее аннотации сервера (`readOnlyHint`,
  `destructiveHint`), не выигрывает молча: расхождение попадает в
  `contract.declaration_vs_annotation`, а `knowledge_state` становится
  `contradictory`;
* неизвестное значение (`"operations": ["TELEPORT"]`) не применяется, а
  записывается в `provenance.declaration_problems`.

Объявление — это вход, а не вывод: оно не понижает серьёзность находки.

### Лексикон — `lexicon`

Глаголы и сигнальные слова классификатора лежат в
`mcp_audit/data/lexicon.json` (категории `operations`, `signals`,
`server_kinds`, `network_kinds`, `kind_roles`). Профиль их дополняет или
заменяет:

```json
"lexicon": {
  "extend": {
    "operations": {"write": ["add", "ack", "checkpoint", "supersede"],
                   "read":  ["traverse", "follow", "taxonomy", "timeline"]},
    "server_kinds": {"memory": "server-memory|memory|knowledge|mempalace"},
    "kind_roles": {"sensitive_source": ["memory"]}
  }
}
```

`extend` добавляет термины (порядок сохраняется, дубли отбрасываются),
`override` заменяет категорию целиком. Каждая категория — список слов
(оборачивается в границу слова) либо объект `{"words": [...], "patterns": [...]}`,
где `patterns` — сырые регулярные выражения. Виды серверов из профиля
проверяются раньше встроенных, `x_audit.kind` в конфиге по-прежнему главнее
всего.

Версия лексикона попадает в `meta.reproducibility.lexicon`
(`"1.0+mempalace:9d1e…"`): два прогона с разными словарями несравнимы, и отчёт
об этом говорит.

Что лексикон **не** делает: он не превращает `UNKNOWN` в догадку. Если стенд
использует слово, которого нет ни в базовом словаре, ни в расширении профиля,
инструмент остаётся `UNKNOWN` — это правильное поведение, а способ сообщить
правду называется `capabilities`.

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

Нужен источник, которого пакет не читает (systemd-юнит, Helm-чарт, свой сервис
политик)? Адаптер пишется рядом, а не внутри:

```json
"adapter_plugins": ["my_pkg.systemd:SystemdAdapter"],
"adapters": [{"id": "units", "kind": "systemd", "binding": {"path": "deploy/app.service"}}]
```

То же делает `--adapter-plugin my_pkg.systemd:SystemdAdapter` в командной
строке и entry point в группе `mcp_audit.adapters`. Плагин, который не
загрузился, попадает в `limitations` отчёта — незагруженный источник никогда не
превращается в пустой список находок.

Адаптер `deployment` принимает либо `docker-compose.yml` (нужен PyYAML), либо
JSON-снимок `{"services": {name: {"image", "ports", "environment", …}}}`.
Значения переменных окружения не сохраняются — только имена ключей.
Манифест в YAML тоже требует PyYAML; в JSON зависимостей нет.

Форматы всех входов адаптеров — в [`adapters_and_formats.md`](adapters_and_formats.md).

## Шаг 4. Прогон

```bash
# 0. проверить профиль до аудита (иначе опечатка придёт в отчёт как unknown)
python -m mcp_audit lint-profile profiles/мой-стенд.json --root . --sources mcp_inventory,policy_snapshot

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
| поток в статусе `unknown` | неверный `path` или `symbol` не найден в файле — `lint-profile` показывает это до аудита |
| 0 инструментов из N найдено | стенд объявляет их не декоратором: задайте `strategy` (`registry_dict`, `list_literal`, `json_file`) |
| инструмент классифицирован как `UNKNOWN` | доменный глагол неизвестен движку: добавьте его в `lexicon.extend` или объявите свойства в `capabilities` |
| ложный `egress` у локального инструмента | объявите `{"egress": false}` в `capabilities` — по коду обработчика, а не по желанию |
| весь `source_facts` в `unknown` на не-Python стенде | нужен `strategy: "regex_only"`; символы ищутся только в Python |
| поток в статусе `contradicted` | паттерн не совпал: либо регулярка неточна, либо код действительно другой |
| `assessment_state: partial` при всех зелёных контролях | какой-то адаптер `partial`/`stale` или есть `unresolved_controls` |
| загрузка манифеста падает | `schema_version` не `"2.0"` либо в файле секретоподобное поле |
| профиль не найден | `profile_ref` резолвится от каталога манифеста; голый id ищется в `profiles/` |
| `inventory_completeness` = «не определено» | не задан `reference_inventory` в профиле и `authorized_tools` в политике |

## Проверка на чужой системе: mempalace

`profiles/mempalace.json` + `examples/mempalace.*` — перенос на систему, которая
писалась без оглядки на этот аудитор
([MemPalace](https://github.com/MemPalace/mempalace), коммит `d9f0590`):
85 python-файлов, MCP-сервер на 8776 строк, 45 инструментов в словаре `TOOLS`,
два режима работы. Аудируется режим общего хаба
(`deploy/docker-compose.server.yml`); локальный stdio-режим исключён из scope
манифеста — там границ доверия нет и правила памяти и идентичности ничего не
значат.

Что понадобилось из нового:

| Механизм | Зачем на этом стенде |
|---|---|
| `strategy: "registry_dict"` | инструменты объявлены словарём `TOOLS`, декоратора нет: было бы 0 из 45 |
| `lexicon.extend` | `add`, `ack`, `checkpoint`, `supersede` / `traverse`, `follow`, `taxonomy`, `timeline`: 11 инструментов из 45 без этого остаются `UNKNOWN`, включая главный путь записи `mempalace_add_drawer` |
| `lexicon.extend.server_kinds` | `mempalace` не совпадал ни с одним встроенным видом сервера |
| `capabilities` | 8 инструментов, чьи свойства из имени не выводятся (`reconnect`, `event_wait`, `artifact_get`, …); объявления сняты с собственного реестра стенда `mempalace/service.py` и с кода обработчиков |

Результат прогона (`python -m mcp_audit audit examples/mempalace.manifest.json`):
45 инструментов классифицированы без единого немотивированного `UNKNOWN`,
17 правил оценено содержательно (8 `FAIL`, 6 `PASS`, 3 `INCONCLUSIVE`), ещё 2
неприменимы и 9 не оценены из-за неподключённых источников — среди находок отсутствие
привязки чтения координационных событий к аутентифицированному агенту (MEM-01),
самозаявленная личность агента (AUTH-01), общий статический токен без отзыва и
без субъекта (AUTH-04) и выдача содержимого артефактов любому предъявителю
токена через `/sync/*` (EGRESS-01). Каждая находка привязана к локатору
`{path, symbol, lines}` в зафиксированном коммите.

Регресс закреплён в `tests/test_mempalace_profile.py`: тест работает от
записанных снимков, поэтому не требует ни клона, ни сети.

Attack-сторона того же переноса — `examples/mempalace.attack.config.json` и
оверлей `mcp_attack/catalog/prompts/domain/mempalace/` — прикручена по образцу
ниже; каждый вариант бьёт по контролю, который аудит показал FAIL, и ссылается
в `notes` на локатор факта. Регресс: `tests/test_mempalace_attack.py`.

## Шаг 7. Attack-сторона — прикрутить `mcp_attack` к тому же стенду

Аудит даёт инвентарь и находки; `mcp_attack` бьёт по ним. Перенос атаки — тоже
данные: один конфиг плюс доменный оверлей каталога, без правок движка (кроме
одной аддитивной записи в `DOMAIN_VALUES` — attack-аналог расширения лексикона).

| Файл | Кто создаёт |
|---|---|
| `<стенд>.attack.config.json` | **руками** — цель (адаптер+binding), каналы, `catalog_paths`, `audit_path`+`audit_mode` |
| `mcp_attack/catalog/prompts/domain/<стенд>/` | **руками** — доменные варианты под контролы, которые аудит показал FAIL |
| `<стенд>.audit.json` | генерируется аудитом; питает ранжирование атаки |

Как выбрать цель и каналы:

* **Адаптер = транспорт стенда.** `openai_compat`/`http_generic` для
  chat-агента, `mcp_client` для MCP-сервера (HTTP или stdio), `callable` для
  in-process библиотеки памяти, `genai_invest` для здешнего стенда. Секрет не
  в конфиге: `credential_ref` → `MCP_ATTACK_CRED_<ref>`.
* **Каналы кодируют модель угроз стенда.** Общий статический токен с
  самозаявленной личностью моделируется одним `credential_ref` на всех каналах
  при разных `principal_id`; изолированные субъекты — разными `credential_ref`.
* **Варианты бьют по находкам, а не абстрактно.** Тэг `rule_ids` варианта
  должен пересекаться с FAIL-контролами аудита — тогда `audit_mode: ranked`
  поднимет их наверх. Каждый вариант — `owasp_amg_category` (для
  `memory_poisoning` обязателен) плюс `taxonomy`/`technique_category`;
  `validate-catalog --strict-taxonomy` это проверяет. Ссылайтесь в `notes` на
  локатор факта из `source_facts`, чтобы атака оставалась привязана к коду.

```bash
# оверлей проходит строгую таксономию
python -m mcp_attack validate-catalog mcp_attack/catalog/prompts/domain/<стенд> --strict-taxonomy
# аудит → атака: снимок аудита ранжирует каталог под свои FAIL-контролы
python -m mcp_attack run --config examples/<стенд>.attack.config.json --out .attack
```

Офлайн (без живого стенда) проверяются загрузка конфига, валидность каталога и
ранжирование по снимку аудита; живой прогон требует доступного стенда, иначе
попытки честно получают `ERROR`/`NOT_EVALUATED`, а не ложный `CLEAN`. Форматы
конфига и адаптеров — в [`attacker.md`](attacker.md).

## Смежные документы

* [`auditor.md`](auditor.md) — режимы, команды, формат отчёта
* [`adapters_and_formats.md`](adapters_and_formats.md) — форматы входов всех адаптеров
* [`rules_catalog.md`](rules_catalog.md) — что требует и что проверяет каждое из 28 правил
* [`audit_subsystem_architecture.md`](audit_subsystem_architecture.md) — архитектура подсистемы
