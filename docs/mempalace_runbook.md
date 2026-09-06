# Перенос аудита на стенд MemPalace

Практический сценарий для [MemPalace](https://github.com/MemPalace/mempalace) —
чужой системы памяти для AI-клиентов (MCP поверх HTTP, общий bearer-токен,
qdrant-бэкенд, mesh-синхронизация с пирами). Общие правила переноса на любой
стенд — в [`porting_to_a_new_stand.md`](porting_to_a_new_stand.md); здесь только
то, что относится к этому стенду: что уже сделано, как это воспроизвести и что
осталось сделать, чтобы закрыть пробелы.

Все числа в документе получены прогоном на коммите MemPalace
`d9f059076c866fa6f29195679d75712436986024` (на 2026-09-06 это HEAD ветки по
умолчанию) и воспроизводятся командами из шага 1.

---

## 1. Состояние: что уже перенесено

Перенос сделан **данными**: `git diff --stat mcp_audit/` после подключения
MemPalace пуст. В репозитории лежат пять файлов и регресс-тест:

| Файл | Что в нём | Кто создаёт |
|---|---|---|
| `profiles/mempalace.json` | 7 компонентов, 3 хранилища памяти, 2 границы, доменный лексикон, 8 объявленных `capabilities`, спецификация `source_facts` (1 объявление инструментов, 11 потоков, 2 перехода авторизации, 1 проверка токена, 2 фоновых задания, 2 точки разрыва) | руками |
| `examples/mempalace.policy.json` | ожидаемая политика: принципалы, `access_rules`, `memory_policy`, `authentication`, `service_rights`, `network`, `egress`, `authorized_tools` (45 имён) | руками |
| `examples/mempalace.manifest.json` | цель, `build_ref`, scope (hub-режим включён, локальный stdio-режим исключён), привязка четырёх адаптеров | руками |
| `examples/mempalace.config.json` | MCP-конфиг клиента: `http://…:8765/mcp`, `live: false` — рукопожатия не было | берётся у стенда |
| `examples/mempalace.source_facts.json` | снимок фактов из кода: 45 объявлений инструментов + 11 потоков с локаторами, sha256 и фрагментами | генерируется |
| `tests/test_mempalace_profile.py` | регресс от записанных снимков — без клона и сети | руками |

Три механизма движка, без которых этот стенд не читается (все — данные профиля,
не код):

| Механизм | Зачем здесь |
|---|---|
| `strategy: "registry_dict"` по символу `TOOLS` | инструменты объявлены модульным словарём, декоратора нет — иначе 0 из 45 |
| `lexicon.extend` | доменные глаголы `add`, `ack`, `checkpoint`, `supersede`, `traverse`, `follow`, `taxonomy`, `timeline` + вид сервера `mempalace`; без них 11 инструментов остаются `UNKNOWN`, включая главный путь записи `mempalace_add_drawer` |
| `capabilities` | 8 инструментов, свойства которых из имени не выводятся; объявления сняты с собственного реестра стенда (`mempalace/service.py`) и с кода обработчиков |

### Результат текущего прогона

```
режим        offline (white_box)
план         25/28 правил; вне плана: TOOL-01 (baseline), EGRESS-02 + INFRA-03 (control_fixtures)
инвентарь    45/45 инструментов, ни одного немотивированного UNKNOWN
контроли     8 FAIL · 6 PASS · 3 INCONCLUSIVE · 2 NOT_APPLICABLE · 9 NOT_EVALUATED
находки      11 подтверждённых (static_supported) + 3 гипотезы
вердикт      partial / findings_present   (exit 0 без --gate, exit 1 с --gate)
```

| Метрика покрытия | Значение | Пробелы |
|---|---|---|
| `inventory_completeness` | 45/45 (100 %) | — |
| `boundary_coverage` | 2/2 (100 %) | — |
| `component_coverage` | 5/8 (62.5 %) | `palace-store`, `knowledge-graph`, `logsync` |
| `mandatory_control_coverage` | 14/26 (53.8 %) | 12 нерешённых контролей (таблица в §5) |
| `mandatory_control_coverage_static` | 14/26 (53.8 %) | — |
| `mandatory_control_coverage_runtime` | **0/26 (0 %)** | наблюдений нет вообще |
| `identity_coverage` | 1/3 (33.3 %) | `agent:READ:event(to_agent)`, `agent:CREATE:drawer` |
| `memory_stage_W/R/C/B` | не определено | нет событий памяти |

Подтверждённые находки (каждая привязана к локатору `{path, symbol, lines}` в
зафиксированном коммите): чтение координационных событий не привязано к
аутентифицированному агенту (MEM-01), владелец и размещение записи приходят
параметром вызова (MEM-03, три потока), retrieval отдаёт записи до применения
политики аудитории (MEM-07), фоновое задание без гарантий согласованности
(MEM-09), самозаявленная личность агента (AUTH-01), авторизация ресурса не
применяется на `mcp-server` (AUTH-02, два перехода), статический общий токен без
отзыва и без субъекта (AUTH-04), выдача содержимого артефактов любому
предъявителю токена через `/sync/*` (EGRESS-01).

---

## 2. Предусловия

* Python 3.11+. `mcp_audit` работает на стандартной библиотеке; `PyYAML` нужен
  только для YAML-манифеста и чтения `docker-compose.yml` напрямую,
  `jsonschema` — только для строгой проверки отчёта по JSON Schema, `pytest` —
  для тестов. `requirements.txt` в корне — зависимости *стенда из этого репозитория*,
  для аудита MemPalace они не нужны.
* Для шага 1 (воспроизведение) — ничего больше: снимки лежат в репозитории.
* Для шага 2 (пересборка фактов) — клон MemPalace на зафиксированном коммите.
* Для §5.3–§5.5 (живой режим) — **своё** развёртывание MemPalace. Аудит чужого
  работающего хаба без письменного разрешения владельца не делается: код читается
  по лицензии MIT, а рукопожатия, фикстуры и трассы — это уже действия на чужой
  системе.

---

## 3. Шаг 1. Воспроизвести офлайн-аудит (без клона и сети)

```bash
cd /path/to/aith_redteaming

# 0. профиль проверяется до аудита
python -m mcp_audit lint-profile profiles/mempalace.json \
    --sources mcp_inventory,policy_snapshot,deployment
# → profiles/mempalace.json: clean
#   planned rules with this profile: 25/28
#   missing: TOOL-01 (baseline), EGRESS-02 INFRA-03 (control_fixtures)

# 1. аудит
mkdir -p .audit
python -m mcp_audit audit examples/mempalace.manifest.json \
    --json .audit/mempalace.json --md .audit/mempalace.md
# → {"status": "partial", "security_conclusion": "findings_present",
#    "confirmed_findings": 11, "hypotheses": 3, "validation_errors": 0, "exit_code": 0}

# 2. структура и ссылочная целостность отчёта
python -m mcp_audit validate .audit/mempalace.json      # → 0 error(s)

# 3. регресс
pip install pytest && python -m pytest tests/test_mempalace_profile.py
```

С `--gate` тот же прогон даёт код возврата **1** (есть подтверждённые находки);
код **2** означал бы неполноту без находок, **4** — ошибку аудита.

---

## 4. Шаг 2. Пересобрать факты из кода

Нужен, когда меняется профиль или коммит MemPalace.

```bash
git clone https://github.com/MemPalace/mempalace /tmp/mempalace
git -C /tmp/mempalace checkout d9f059076c866fa6f29195679d75712436986024

# локаторы и регулярки проверяются по реальному дереву
python -m mcp_audit lint-profile profiles/mempalace.json --root /tmp/mempalace \
    --sources mcp_inventory,policy_snapshot,deployment

python -m mcp_audit source-snapshot --profile profiles/mempalace.json \
    --root /tmp/mempalace \
    --commit d9f059076c866fa6f29195679d75712436986024 \
    --repository MemPalace/mempalace \
    -o examples/mempalace.source_facts.json
# → source facts written: 45 declaration(s), 11 flow(s)
```

Проверено: пересобранный файл побайтово совпадает с зафиксированным в
репозитории (отличается только `captured_from.captured_at`; `--repository`
обязателен, иначе поле уедет в `null`).

### Если MemPalace ушёл вперёд

Снимок — это утверждение о конкретном коммите, поэтому «просто обновить клон»
нельзя. Порядок:

1. `git -C /tmp/mempalace checkout <новый sha>`;
2. `lint-profile --root` — покажет исчезнувшие `path`/`symbol` до аудита;
3. `source-snapshot` с новым `--commit`;
4. разобрать статусы в новом файле фактов: `contradicted` = код изменился и
   больше не подтверждает утверждение профиля (не «регулярка сломалась» —
   сначала прочитать код); `unknown` = файл или символ переехали;
5. обновить `build_ref` в `examples/mempalace.manifest.json`, `commit` в
   `examples/mempalace.deployment.json` и пин в `tests/test_mempalace_profile.py`;
6. прогнать §3 и сравнить набор находок с прошлым — изменение вердикта без
   изменения профиля означает изменение стенда.

---

## 5. Что осталось сделать

Карта нерешённого. Формулировки в колонке «чего не хватает» — это то, что движок
сам пишет в `limitations`/`interpretation` соответствующего контроля.

| Контроль | Сейчас | Чего не хватает | Куда это класть | Раздел |
|---|---|---|---|---|
| MEM-06 | NOT_EVALUATED | «no trust-elevation / approval flows and no shared records available» | поток `trust_elevation` в профиле | §5.1 |
| MEM-08 | NOT_EVALUATED | «no revocation events» (stage D) | потоки `revocation_check` + события отзыва | §5.1 / §5.4 |
| MEM-10 | INCONCLUSIVE | нет ожиданий retention в политике для `drawer`/`kg_fact`; поведение retention не найдено в коде для `event`/`artifact` | `policy.retention` + потоки `retention` | §5.1 |
| AUTH-03 | NOT_EVALUATED | «no security-mode flows or client-weakening attributes declared» | поток `security_mode`, атрибут `client_can_weaken` | §5.1 |
| AUTH-05 | NOT_EVALUATED | «no delegation attributes on transitions» | `delegation`/`subject_bound` на переходе | §5.1 |
| AUTH-06 | NOT_EVALUATED | «no revocation-check flows» (stage D) | поток `revocation_check` + трасса | §5.1 / §5.4 |
| INFRA-01 | INCONCLUSIVE | «qdrant: not a known storage image» и нет фактов доступа к хранилищу | потоки `store_access` | §5.1 |
| TOOL-04 | NOT_EVALUATED | «no chain from tool results to policy/publication declared» | `profile.chains` | §5.1 |
| TOOL-05 | INCONCLUSIVE | 3 текстовых сигнала записаны гипотезами — нужен разбор человеком | вывод в отчёте | §5.6 |
| TOOL-01 | NOT_EVALUATED | источник `baseline` не привязан | `mcp_audit baseline` + реестр одобрений | §5.2 |
| TOOL-02 | NOT_EVALUATED | «only one definition source per tool; contracts cannot be compared» | живое рукопожатие как второй источник определений | §5.3 |
| INV-02 | NOT_EVALUATED | «discovery not performed in this mode» | режим `live-inventory` | §5.3 |
| EGRESS-02 | NOT_APPLICABLE | «no controlled validation in this mode» | `control_fixtures` | §5.5 |
| INFRA-03 | NOT_APPLICABLE | «no controlled validation in this mode» | `control_fixtures` + декларация изоляции | §5.5 |

Порядок ниже — по возрастанию цены: §5.1 не требует ничего, кроме чтения кода;
§5.3–§5.5 требуют поднятого стенда.

### 5.1. Только данные: дописать профиль и политику

Каждая запись — утверждение о коде, которое движок обязан подтвердить или
опровергнуть. Пишите паттерны **от реального кода** и сразу прогоняйте
`source-snapshot`: `contradicted` читается как «код противоречит заявленному».
Якоря в коммите `d9f0590`, найденные при подготовке этого документа, — стартовые
точки, а не готовые факты:

| Что добавить | Правило | Куда смотреть в MemPalace |
|---|---|---|
| поток `store_access` от `mcp-server` и `miner` к `palace-store` с фактическими `rights` | INFRA-01 | `mempalace/backends/qdrant.py`: `_QdrantRESTClient` (`upsert_points`, `delete_points`, `create_collection`), ключ `api-key` из `MEMPALACE_QDRANT_API_KEY` |
| поток `security_mode` + `client_can_weaken` на переходе | AUTH-03 | `mempalace/mcp_server.py:326–329` (`_READ_ONLY` из `--read-only` / `MEMPALACE_MCP_READ_ONLY`), `mcp_server.py:8182–8189` (токен обязателен только при небиндовом на loopback) |
| атрибуты `delegation` / `subject_bound` на переходе `sync-pull` | AUTH-05 | `mempalace/logsync.py`, `mempalace/hub_client.py`, `mempalace/mcp_proxy.py` — чем именно ограничен пир, кроме владения токеном |
| потоки `revocation_check` и `retention` | AUTH-06, MEM-08, MEM-10 | `mempalace/knowledge_graph.py:343` (`invalidate`), инструменты `kg_invalidate`/`kg_supersede`, `mempalace/sweeper.py:203` (`sweep`), `mempalace/backups.py` |
| поток `trust_elevation` | MEM-06 | `mempalace/convo_miner.py:875` (`mine_convos`) и `mempalace/miner.py` (`_build_drawer_metadata` — уже описан в профиле, но как `derivation`): попадает ли добытое в общую память без ревью |
| `retention` в политике для `drawer` и `kg_fact` | MEM-10 | ожидание владельца стенда, а не код |
| цепочка «результат инструмента → политика/публикация» в `profile.chains` | TOOL-04 | сейчас объявлена одна цепочка (`peer-content-to-agent-context`) |
| факты, называющие `palace-store`, `knowledge-graph`, `logsync` | `component_coverage` 5/8 → выше | те же файлы |

После правок — обязательно `lint-profile --root` и `source-snapshot`, затем §3.

Две честные оговорки. INFRA-01 **не станет `PASS`** даже с корректными
`store_access`: сервис `qdrant` даёт отдельное `INCONCLUSIVE`-утверждение
(«authentication not shown in this configuration»), потому что адаптер
deployment знает подсказки аутентификации только для redis/mongo/postgres/mysql,
а значения переменных окружения не читает принципиально. Правило поднимется до
`FAIL` при превышении прав над политикой — зелёным по этому стенду оно станет
только по наблюдению реального развёртывания. MEM-08 и AUTH-06 — контроли
stage D: без событий отзыва (§5.4) они останутся частичными.

### 5.2. Baseline → TOOL-01

```bash
python -m mcp_audit baseline examples/mempalace.manifest.json -o .audit/mempalace.baseline.json
python -m mcp_audit audit examples/mempalace.manifest.json --baseline .audit/mempalace.baseline.json
```

Проверено: TOOL-01 переходит в `PASS` («all definitions match the approved
baseline»), нерешённых контролей становится 11 вместо 12.

Оговорка, которую нельзя терять: свежий снимок печатает
`approval_state=unknown` и несёт в себе строку «a new snapshot is not approved by
being produced by the auditor». Аудитор не одобряет определения — одобрения
приходят из реестра через `--approvals` (`{"approvals": {"mempalace/tool":
{"state": "approved", "hash": "...", "by": "...", "at": ...}}}`). Baseline имеет
смысл фиксировать один раз на коммит и потом сравнивать:

```bash
python -m mcp_audit drift examples/mempalace.manifest.json \
    --baseline .audit/mempalace.baseline.json --approvals approvals.json --fail-on-drift
```

### 5.3. Живой хаб → `live-inventory` (INV-02, TOOL-02)

Поднять **своё** развёртывание по инструкции стенда:

```bash
cd /tmp/mempalace
cp deploy/server.env.example deploy/.env
# MEMPALACE_MCP_HTTP_TOKEN=$(openssl rand -hex 32)
docker compose -f deploy/docker-compose.server.yml --env-file deploy/.env up -d
```

Гигиена: отдельный пустой qdrant и отдельный `mempalace-data`, никакого рабочего
palace команды; сеть закрыта наружу; хаб слушает открытый HTTP на 8765 — держать
его в изолированной сети. Для первого рукопожатия достаточно `--read-only`.

Затем — копия манифеста с живой привязкой (сам манифест из репозитория не
трогаем, у него зафиксирован офлайн-scope):

```json
{"id": "mcp-config", "kind": "mcp_inventory",
 "binding": {"path": "mempalace.config.json", "live": true,
             "credential_binding": "MEMPALACE", "identity": "audit-client"}}
```

```bash
export MCP_AUDIT_CRED_MEMPALACE="Bearer $MEMPALACE_MCP_HTTP_TOKEN"
python -m mcp_audit audit examples/mempalace.live.manifest.json --mode live-inventory \
    --json .audit/mempalace.live.json
```

Токен в манифест не кладётся: непустые поля `token`/`secret`/`authorization`
отклоняют файл целиком, поэтому учётные данные передаются только именем привязки
(`credential_binding: "NAME"` → переменная `MCP_AUDIT_CRED_NAME`, по умолчанию
заголовок `Authorization`).

Что это даёт: `INV-02` получает реальный discovery вместо «configured catalogue
only», а `TOOL-02` — второй источник определений (`tools/list` против словаря
`TOOLS`), после чего контракты становятся сравнимыми. Рукопожатие также
переводит `knowledge_state` инструментов из `assumed` в `known` — сейчас все 45
объявлений остаются словом автора профиля. Помните, что рукопожатие показывает
каталог **одной** личности: `identity` в привязке подписывает, чьей, — отсутствие
инструмента в этом ответе не доказывает его отсутствия для другой роли.

### 5.4. Наблюдения: `trace` и `memory_events`

Новых правил не открывают (потолок остаётся 25/28 + baseline + фикстуры), но
делают две вещи, которых офлайн-режим не может: переводят статусы находок из
`static_supported` в `runtime_supported` и заполняют стадии памяти W/R/C/B
(сейчас все четыре — «не определено», а `mandatory_control_coverage_runtime` —
0/26).

* `memory_events` (`schema: "memory-events"`) — записи и события памяти с
  `field_map` и `coverage`; без `coverage` отсутствие события не считается
  наблюдением. Источник на этом стенде — коллекции qdrant и журнал `logstream`.
* `trace` (JSONL) — события с `event_id`/`run_id`/`trace_id`/`component`/
  `principal` и блоками `memory` / `tool` / `flow` / `observation` / `job`.
  Первая строка может нести `{"_coverage": {...}}`.

Форматы — в [`adapters_and_formats.md`](adapters_and_formats.md); привязка:
`--memory-events`, `--trace`, режим `trace-review`. Именно здесь закрываются
`identity_coverage` (`agent:READ:event(to_agent)`, `agent:CREATE:drawer`) и
события отзыва для MEM-08/AUTH-06.

### 5.5. Контролируемая проверка → EGRESS-02, INFRA-03

Единственные два правила, которые нельзя закрыть ни кодом, ни политикой: нужен
зарегистрированный контрольный случай, выполненный внутри объявленной изоляции.
Файл `schema: "control-fixtures"` содержит `isolation`
(`data: synthetic`, `network`, `permissions`, `attested_by`), `roots`, `cases` с
`expected_invariant` и `effect_check`; плейсхолдеры `{canary}`, `{sinkhole}`,
`{root}`.

Для этого стенда осмысленные случаи — вокруг подтверждённой находки EGRESS-01:
запрос содержимого артефакта через `/sync/*` предъявителем токена, где
`effect_check` — `sink_received` на подставном пире (канареечное содержимое,
синтетические данные, сеть замкнута на sinkhole).

```bash
python -m mcp_audit audit examples/mempalace.live.manifest.json \
    --mode controlled-validation --fixtures examples/mempalace.fixtures.json --sandbox
```

`--sandbox` — это декларация намерения, а не доказательство изоляции; сама
изоляция заявляется в фикстуре и попадает в отчёт как утверждение. Разрушающие
случаи не выполняются без `--allow-destructive`. Случай, аргументы которого не
согласуются со схемой инструмента, не выполняется вовсе (`error_class =
schema_error | unknown_tool` → `INCONCLUSIVE`), а без `effect_check` нарушение не
заявляется.

### 5.6. Разбор трёх гипотез (TOOL-05)

В описаниях инструментов найдены императив, обращённый к модели, и два
свободных sink-параметра. Это записано гипотезами с фрагментом, правилом и
объяснением — императив, юникод или ссылка сами по себе не доказывают злого
умысла. Нужен вывод человека: либо находка с обоснованием, либо явное
объявление в `capabilities` по коду обработчика (объявление — вход, а не вывод:
оно не понижает серьёзность находки, а `classification_basis` в отчёте всегда
показывает `declared`).

---

## 6. Чего делать нельзя

* **Править `mcp_audit/` под MemPalace.** Правила системно-независимы; если
  что-то не выражается профилем — это повод обсудить новое правило, а не
  захардкодить имя стенда. Проверка: `git diff --stat mcp_audit/` после переноса
  должен быть пуст.
* **Класть секреты в манифест, политику или профиль.** Только
  `credential_binding` и переменные `MCP_AUDIT_CRED_*`.
* **Подменять улику объявлением.** `capabilities` и политика — это заявленные
  ожидания; `knowledge_state` остаётся `assumed`, пока нет рукопожатия или кода.
* **Обновлять клон без перепина.** Снимок фактов без совпадающего `build_ref` —
  это утверждение о версии, которой нет.
* **Трогать чужой работающий хаб.** Живые режимы — только на своём развёртывании.

---

## 7. Чек-лист приёмки переноса

- [ ] `lint-profile` — `clean`, планируемых правил не меньше 25
- [ ] `source-snapshot` пересобирается из клона и совпадает с зафиксированным файлом
- [ ] в файле фактов нет `unknown`/`contradicted` без объяснения
- [ ] `audit` + `validate` — `0 error(s)`
- [ ] `tests/test_mempalace_profile.py` зелёный
- [ ] каждая находка имеет `claim_refs` и `closure_criterion`, а улики — `build_ref` коммита
- [ ] `unresolved_controls` в отчёте объяснены: для каждого известно, какой источник его закроет (таблица §5)
- [ ] `git diff --stat mcp_audit/` пуст

---

## 8. Что дальше: атака по результатам аудита

Отчёт аудита — вход для red-team харнесса: находки приоритизируют каталог атак
по `rule_ids` / `owasp_amg_category`.

```bash
python -m mcp_attack run --config <target>.attack.config.json \
    --audit .audit/mempalace.json --audit-mode ranked --audit-min-severity HIGH
```

Для MemPalace в hub-режиме подходит адаптер `mcp_client` (grey-box, `tools/call`
поверх streamable HTTP) — и снова только против своего развёртывания.
Подробности — в [`attacker.md`](attacker.md).

---

## Смежные документы

* [`porting_to_a_new_stand.md`](porting_to_a_new_stand.md) — общий сценарий переноса на любой стенд
* [`adapters_and_formats.md`](adapters_and_formats.md) — форматы входов всех адаптеров
* [`rules_catalog.md`](rules_catalog.md) — что требует и что проверяет каждое из 28 правил
* [`auditor.md`](auditor.md) — режимы, команды, формат отчёта
* [`attacker.md`](attacker.md) — red-team харнесс
