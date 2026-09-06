# План: перенос аудита на любой стенд только данными

Цель работы — довести `mcp_audit` до состояния, в котором подключение нового
стенда не требует ни одной правки внутри пакета. Приёмочный стенд —
[MemPalace/mempalace](https://github.com/MemPalace/mempalace): чужая система,
написанная без оглядки на наш аудитор (85 python-файлов, MCP-сервер на 8776
строк, 45 инструментов, пять сменных бэкендов памяти, два режима работы).

Документ описывает диагностику, состав изменений, порядок работ и критерии
приёмки. Он дополняет [`porting_to_a_new_stand.md`](porting_to_a_new_stand.md),
который описывает перенос *с точки зрения автора профиля*; здесь — что для
этого нужно поменять *в самом аудиторе*.

## 0. Критерий готовности

Перенос на новый стенд считается «только данными», если выполнено всё:

1. Написаны ровно три файла: `profiles/<стенд>.json`, `<стенд>.policy.json`,
   `<стенд>.manifest.json` (плюс генерируемые снимки: `source_facts`, baseline).
2. `git diff --stat mcp_audit/` после подключения стенда пуст.
3. `python -m mcp_audit lint-profile profiles/<стенд>.json` завершается кодом 0.
4. `python -m mcp_audit audit <стенд>.manifest.json` даёт отчёт, проходящий
   `validate`, с честной картой пробелов в `plan.entries`.

**Что в цель не входит.** Секция `source_facts` остаётся ручной работой по
определению: это утверждения о конкретном коде с конкретными регулярными
выражениями, и именно их фальсифицируемость (статус `contradicted`) даёт
методу ценность. «Только данными» означает «без правок пакета», а не «профиль
напишется сам».

## 1. Что уже системно-независимо и не трогается

Проверено чтением кода, а не декларацией:

* **Правила не знают о стендах.** `grep -rn "invest\|genai\|mempalace" mcp_audit/`
  даёт два совпадения, оба вне логики: слово «investigate» в тексте remediation
  (`inventory_rules.py:75`) и ссылка на OWASP (`memory_rules.py:594`).
* **Правила читают только данные.** Весь доступ идёт через `RuleContext`
  (`control_rules/base.py:22`): `ctx.flows(kind)`, `ctx.profile`, `ctx.policy`,
  `ctx.facts`, `ctx.memory_types_declared()`, `ctx.chain_state()`. Прямых
  обращений к именам компонентов в правилах нет.
* **Реестр адаптеров — декораторный** (`adapters/registry.py`), новый вид
  источника не требует правки диспетчера.
* **Локатор символов уже шире, чем кажется**: `SourceScanner.symbol()`
  (`adapters/source_snapshot.py:118`) находит не только `FunctionDef`/`ClassDef`,
  но и `ast.Assign` — то есть модульные словари-реестры уже адресуемы.
* **Приоритет «объявлено > выведено» заложен в моделях**: `field_sources`,
  `provenance["classification"]`, `knowledge_state`, `classification_basis`.
  Нужно достроить пути записи, а не менять модель.

Эти четыре свойства — фундамент. Ни одно изменение ниже их не ломает.

## 2. Диагностика: где стенд сейчас требует кода

| # | Точка | Файл | Что ломается на mempalace | Приоритет |
|---|---|---|---|---|
| 1 | извлечение объявлений инструментов только по декоратору | `adapters/source_snapshot.py:142` | инструменты объявлены словарём `TOOLS`, не декоратором → 0 из 45 найдено | P0 |
| 2 | нет способа объявить свойства инструмента данными | `discovery/config_parser.py:70` | `x_audit` читается только на уровне сервера; per-tool переопределения нет | P0 |
| 3 | профиль ничем не валидируется | `validation/schema.py:153` | опечатка в `path`/`symbol` даёт молчаливый `unknown`, неотличимый от «код другой» | P0 |
| 4 | лексикон классификатора зашит в код | `classification/classifier.py:24-49` | доменные термины стенда неизвестны → ¼ инвентаря классифицируется неверно | P1 |
| 5 | список видов серверов зашит в код | `discovery/config_parser.py:31` | `kind` угадывается регуляркой; для нового стенда — лотерея | P1 |
| 6 | исходники разбираются только как Python; deployment — только compose/JSON | `adapters/source_snapshot.py:98`, `adapters/deployment.py` | mempalace на Python (не мешает), но `deploy/mempalace-server.service` не читается | P2 |

### 2.1 Измерение: классификация 45 инструментов mempalace

Инструменты извлечены из `TOOLS` (`mempalace/mcp_server.py:5093`) и прогнаны
через текущий `classify_tool` с `server_kind="memory"`:

```
READ 18    WRITE 12    UNKNOWN 11    DELETE 4
```

Разбор ошибок:

| Инструмент | Получено | Должно быть | Причина |
|---|---|---|---|
| `mempalace_add_drawer` | `UNKNOWN` | `WRITE`/`CREATE` | в `_WRITE` (`classifier.py:33`) нет глагола «add»; `_CREATE`, где он есть, применяется только *после* выбора WRITE |
| `mempalace_kg_add`, `mempalace_kg_invalidate`, `mempalace_event_ack` | `UNKNOWN` | запись | то же |
| `mempalace_kg_supersede` | `READ` | запись | доменный термин, совпал с чтением по описанию |
| `mempalace_traverse`, `mempalace_follow_tunnels`, `mempalace_graph_stats`, `mempalace_kg_timeline`, `mempalace_kg_stats`, `mempalace_status`, `mempalace_reconnect` | `UNKNOWN` | чтение / служебное | доменные термины стенда (drawer, wing, tunnel, hallway, mine) движку неизвестны |
| `mempalace_event_wait`, `mempalace_task_create` | `egress=True` | `False` | ложное срабатывание `_EGRESS` |
| `mempalace_get_drawer`, `mempalace_artifact_get` | `egress=True` | `False` | то же |

Итог: **11 из 45 без классификации и ещё несколько классифицированы неверно**,
причём в числе неклассифицированных — `mempalace_add_drawer`, главный путь
записи в память, то есть вход для MEM-01/03/05. Объявить правду данными
сейчас негде.

Отдельно важно: то, что неизвестное остаётся `UNKNOWN`, а не угадывается, —
**правильное** поведение (`knowledge_state = UNKNOWN`), и оно сохраняется.
Чинить нужно не строгость, а отсутствие способа сообщить факт.

## 3. Состав изменений

### P0-1. Стратегии извлечения объявлений инструментов

**Сейчас.** `SourceScanner.tool_declarations(rel, decorator)` обходит AST и
берёт функции с декоратором `@tool` / `@mcp.tool`. Иных форм объявления нет.

**Станет.** Способ извлечения задаётся профилем:

```json
"tool_declarations": [
  {"component": "mcp-server", "path": "mempalace/mcp_server.py", "kind": "mcp",
   "strategy": "registry_dict", "symbol": "TOOLS",
   "schema_key": "input_schema", "description_key": "description"}
]
```

Стратегии:

| `strategy` | Форма объявления | Как читается |
|---|---|---|
| `decorator` (по умолчанию) | `@tool` / `@mcp.tool` над функцией | текущая реализация, поведение не меняется |
| `registry_dict` | модульный словарь `{имя: {описание, схема, handler}}` | `symbol()` находит `ast.Assign`, значения читаются `ast.literal_eval` с падением в `unknown` при неконстантном значении |
| `list_literal` | список словарей определений | то же |
| `json_file` | определения вынесены в JSON/YAML рядом с кодом | читается файл, фиксируется его `sha256` |

Контракт результата не меняется: каждая запись кладётся в
`facts["tool_declarations"]` с полями `component`, `kind`, `name`,
`description`, `input_schema`, `status`, локатором `{path, symbol, lines}` и
дайджестом. Отсутствие `strategy` = `decorator`, поэтому существующие профили
не трогаются.

**Тесты.** Фикстура с реестром-словарём; проверка, что имена, описания и схемы
совпадают с ожидаемыми; проверка `unknown` при вычисляемом (неконстантном)
значении вместо тихого пропуска.

Объём: ~40 строк реализации, ~60 строк тестов.

### P0-2. Явные объявления возможностей: declared > heuristic > unknown

**Сейчас.** Свойства инструмента (`classification`, `operations`, `egress`,
`destructive`, `sensitive_source`, `untrusted_input`) выводятся исключительно
эвристиками `classify_tool` плюс MCP-аннотации `readOnlyHint`/`destructiveHint`.
`x_audit` в конфиге действует только на сервер целиком.

**Станет.** Два места, где то же самое объявляется явно.

В MCP-конфиге, рядом с определением инструмента:

```json
{"name": "mempalace_add_drawer", "description": "…", "inputSchema": {…},
 "x_audit": {"operations": ["CREATE"], "egress": false, "sensitive_source": true}}
```

Или в профиле, если конфиг стенда трогать нельзя:

```json
"capabilities": {
  "mempalace/mempalace_add_drawer": {"operations": ["CREATE"], "egress": false},
  "mempalace/mempalace_kg_supersede": {"operations": ["UPDATE"]}
}
```

Правило разрешения — строго в этом порядке:

1. **declared** — объявление в конфиге или профиле;
2. **annotation** — `readOnlyHint` / `destructiveHint` из handshake
   (самоотчёт сервера, уже помечается как таковой);
3. **heuristic** — `classify_tool`;
4. **unknown** — если ничто не сработало.

Источник записывается в `classification_basis` (`declared` / `annotation(self-report)` /
`definition:name` / `definition:description` / `none`) и в
`provenance["classification"]`. `knowledge_state` при `declared` остаётся
`ASSUMED`: объявление — это заявление автора конфига, а не наблюдение, и
`KNOWN` по-прежнему требует улики из handshake или кода. Отчёт обязан отличать
«мы это знаем, потому что нам сказали» от «мы это угадали по имени» — иначе
объявление превращается в способ нарисовать зелёный вердикт.

**Чего не делаем.** Не заменяем `UNKNOWN` догадкой и не позволяем объявлению
понижать серьёзность находки без улики: объявление — это вход, а не вывод.

**Влияние на правила.** TOOL-02 получает второй источник контракта и начинает
сравнивать, а не молчать (`tool_rules.py:68` сейчас возвращает
`not_evaluated: only one definition source per tool`). EGRESS-01 получает
осмысленный список egress-способных инструментов вместо ложных срабатываний.

**Тесты.** Объявление бьёт эвристику; `classification_basis` отражает источник;
объявление, противоречащее аннотации сервера, фиксируется как расхождение,
а не молча выигрывает.

### P0-3. Валидатор профиля: `mcp_audit lint-profile`

**Сейчас.** `validate_document` проверяет только итоговый отчёт. Профиль не
проверяется ничем: опечатка в `path` даёт `unknown`, опечатка в имени секции —
тихий пропуск, несуществующий `rule_refs` — ничего. Человек не может отличить
«код действительно другой» от «я ошибся в данных». Для режима «меняю только
данные» это главный источник боли.

**Станет.** Отдельная команда, проверяющая пять вещей:

1. структура профиля по JSON-схеме (`schemas/profile.schema.json`);
2. каждый `path` существует в дереве исходников, каждый `symbol` находится;
3. каждая регулярка компилируется;
4. каждый `rule_refs` есть в каталоге правил;
5. ссылочная целостность: `component`, `from`, `to`, `writer_principal`,
   `boundary` ссылаются на объявленные сущности.

Плюс сводка, **какие правила профиль в принципе открывает** — та же таблица,
что в `porting_to_a_new_stand.md`, но посчитанная по конкретному профилю:

```
$ python -m mcp_audit lint-profile profiles/mempalace.json --root ../mempalace
profiles/mempalace.json: 3 problem(s)

  flows[R-drawer-write].symbol   'Palace.add_drawer' not found in mempalace/palace.py
  flows[R-search].patterns[1]    invalid regex: unbalanced parenthesis
  auth_transitions[AT-hub].boundary  'HB-hub' is not declared in boundaries[]

planned rules with this profile: 17/28
  missing: TOOL-01 (baseline), EGRESS-02 INFRA-03 (fixtures), MEM-08 MEM-10 (policy), …
```

Коды возврата: `0` — чисто, `1` — есть проблемы, `4` — профиль не читается.

**Тесты.** Профиль с известной опечаткой даёт ровно одну ожидаемую строку;
эталонные профили (`genai_invest_stand`, `rest_native_agent`) проходят чисто.

### P1-4. Лексикон классификатора — в данные

**Сейчас.** Восемь регулярных выражений в `classifier.py:24-49` — это зашитая
лингвистика: английский плюс русский, плюс доменная лексика первого стенда
(`portfolio|holdings|broker|дивиденд|сдел\w+`). Любой новый домен требует
патча пакета.

**Станет.** `mcp_audit/data/lexicon.json`:

```json
{"lexicon_version": "1.0",
 "operations": {"write": ["write","create","add","update","…"],
                "delete": ["delete","remove","purge","…"],
                "read":   ["read","get","list","search","…"],
                "exec":   ["exec","shell","spawn","…"]},
 "signals": {"egress": [...], "sensitive": [...], "untrusted": [...], "transmit": [...], "publish": [...]},
 "server_kinds": {"memory": "server-memory|memory|knowledge", "…": "…"},
 "network_kinds": ["fetch","github","gitlab","slack","email"]}
```

Профиль дополняет и переопределяет:

```json
"lexicon": {"extend": {"operations": {"write": ["mine","checkpoint","supersede","append"],
                                      "read":  ["traverse","follow","taxonomy"]}}}
```

`extend` добавляет, `override` заменяет целиком. Версия лексикона попадает в
`reproducibility`, иначе два прогона с разными словарями несравнимы.

**Регрессия обязательна.** Существующий стенд должен классифицироваться в
точности как раньше: тест сравнивает классификацию всех инструментов
`genai_invest_stand` до и после выноса.

### P1-5. Виды серверов — в данные

`_KNOWN_KINDS` (`config_parser.py:31`) и `_NETWORK_KINDS` (`classifier.py:49`)
переезжают в тот же `lexicon.json`. `x_audit.kind` остаётся приоритетным
источником — этот механизм уже работает правильно.

### P2-6. Плагины адаптеров

`adapters/registry.py` пополняется только импортами внутри пакета. Добавляем
загрузку снаружи: `--adapter-plugin module:Class` в CLI и `adapters` в
entry points. Практический повод виден уже на mempalace: адаптер `deployment`
читает compose и JSON, а `deploy/mempalace-server.service` (systemd) придётся
конвертировать руками. С плагинами адаптер systemd/k8s/Helm пишется рядом, не
внутри.

### P2-7. Исходники не на Python

`SourceScanner.read` (`:98`) делает `ast.parse` для `.py`, а для остального
возвращает пустой модуль — то есть на TypeScript-стенде **весь** `source_facts`
молча уходит в `unknown`, и это выглядит как «код не подтверждает профиль».
Минимальное исправление в два шага:

1. `strategy: "regex_only"` — локатор «файл + диапазон строк» вместо символа,
   чтобы `static_supported` / `contradicted` работали без AST;
2. явная причина в статусе: `unknown (language not supported: .ts)` вместо
   безмолвного `unknown`.

Для mempalace не требуется (он на Python), для «разных стендов» — обязательно.

## 4. Приёмочный стенд: mempalace

### 4.1 Режим

У mempalace два режима, и они дают разный аудит:

* **local stdio** — один пользователь, границ доверия нет; MEM-правила про
  `audience`/`authority` и все AUTH-* схлопываются;
* **shared hub** — `deploy/docker-compose.server.yml`, bearer-токен
  (`MEMPALACE_MCP_HTTP_TOKEN`), сетевой бэкенд (qdrant), межузловой транспорт
  (`transport.py:135`, `peers.json`), делегирование через
  `mempalace_task_create` / `event_*` / `artifact_*` / `patch_submit`.

**Аудируем hub-режим** — только там правила памяти и идентичности что-то
значат. Local-режим фиксируется в `scope` манифеста как невключённый.

### 4.2 Что пишется

| Файл | Содержание |
|---|---|
| `profiles/mempalace.json` | компоненты (mcp-сервер, палата/бэкенд, hub, mesh-пиры, фоновые задания), `memory_stores`, `boundaries`, `tool_declarations` со `strategy: registry_dict`, `lexicon.extend` с доменными терминами, `source_facts` |
| `examples/mempalace.policy.json` | ожидаемая политика: кто читает чужую память в общем палате, что считается доверенным издателем, retention |
| `examples/mempalace.manifest.json` | `schema_version: "2.0"`, `build_ref` = коммит клона, адаптеры: `mcp_inventory`, `source_snapshot`, `policy_snapshot`, `deployment` |

Клон mempalace — вход адаптеров, а не часть репозитория: он получается
`git clone` на момент прогона, а версия фиксируется через `build_ref` в
манифесте (он подмешивается в `scope` каждой улики). Push в чужой репозиторий
невозможен и не нужен.

### 4.3 Целевой охват

| Этап | Источники | Правил оценивается |
|---|---|---|
| скелет | конфиг + deployment | ~3 содержательно (TOOL-05, INFRA-02, INV-02); остальное `not_evaluated` |
| срез памяти | + `source_facts`: 5–8 потоков (`add_drawer` → бэкенд, `search` → бэкенд, `context_include`, `derivation` в `miner.py`/`llm_refine.py`) | +MEM-01/03/04/05/07, INV-01, TOOL-02 |
| hub-идентичность | + 1–2 `auth_transitions`, `token_validation` по bearer-токену | +AUTH-02/04 |
| политика | + `policy.json` | +INFRA-01, MEM-08, MEM-10 |

Целевое состояние приёмки — **12–15 оценённых правил на чужой системе**, и
среди них обязательно должно быть хотя бы одно `FAIL` или `contradicted`:
демонстрация, в которой движок не может возразить автору профиля, ничего не
демонстрирует.

Отдельный кандидат в находки уже виден: mempalace хранит содержимое дословно
и отдаёт его в контекст модели, а 45 описаний инструментов написаны
императивно — это прямой материал для MEM-04 (данные против инструкций) и
TOOL-05.

## 5. Этапы и оценки

| Этап | Содержание | Оценка |
|---|---|---|
| 1 | P0-3 `lint-profile` + схема профиля | 0.5–0.75 дня |
| 2 | P0-1 стратегии извлечения + тесты | 0.5 дня |
| 3 | P0-2 явные объявления возможностей + тесты | 0.5 дня |
| 4 | P1-4, P1-5 лексикон и виды серверов в данные + регресс на текущем стенде | 0.5 дня |
| 5 | Профиль/политика/манифест mempalace, скелетный прогон | 0.5 дня |
| 6 | Срез памяти и hub-идентичности в `source_facts`, доводка до 12–15 правил | 1–1.5 дня |
| 7 | Тест `tests/test_mempalace_profile.py`, обновление документации | 0.5 дня |
| | **Итого P0+P1+приёмка** | **4–5 дней** |
| 8 | P2-6 плагины адаптеров, P2-7 не-Python | +1–2 дня, по необходимости |

Порядок не случаен: `lint-profile` идёт первым, потому что все последующие
этапы им пользуются — без него отладка профиля mempalace превращается в
угадывание, почему правило `not_evaluated`.

## 6. Критерии приёмки

- [ ] `git diff --stat mcp_audit/` пуст после подключения mempalace
- [ ] `lint-profile` на трёх профилях (`genai_invest_stand`, `rest_native_agent`, `mempalace`) даёт код 0
- [ ] Классификация инструментов `genai_invest_stand` побитово совпадает с доэталонной (регресс лексикона)
- [ ] Все 45 инструментов mempalace имеют классификацию с `classification_basis` ∈ {`declared`, `definition:*`}; ни одного немотивированного `UNKNOWN`
- [ ] Аудит mempalace даёт ≥12 оценённых правил и ≥1 `FAIL` или `contradicted`
- [ ] Отчёт проходит `python -m mcp_audit validate` без ошибок
- [ ] `tests/test_mempalace_profile.py` зелёный в CI
- [ ] `porting_to_a_new_stand.md` обновлён: стратегии извлечения, `capabilities`, `lexicon`, `lint-profile`

## 7. Риски и осознанные ограничения

| Риск | Ответ |
|---|---|
| Явные объявления превращаются в способ нарисовать зелёный вердикт | `classification_basis` и `knowledge_state` обязаны отличать объявленное от наблюдаемого; объявление не понижает серьёзность находки без улики |
| Вынос лексикона меняет вердикты на существующем стенде | регресс-тест на полном инвентаре `genai_invest_stand`, версия лексикона в `reproducibility` |
| `source_facts` для mempalace пишется по коду, который меняется | `build_ref` в манифесте, `sha256` каждого файла в фактах; расхождение видно как `contradicted`, а не как тихий проход |
| Профиль mempalace окажется подгонкой под правила | принимаем только тот срез, где есть `contradicted`/`FAIL`; отсутствие возражений движка — признак подгонки, а не успеха |
| Соблазн добавить правило под mempalace | правила не трогаем вообще; если свойство не выражается профилем — это отдельный разговор о новом системно-независимом правиле, не в рамках этой работы |

## 8. Что меняется в документации

* [`porting_to_a_new_stand.md`](porting_to_a_new_stand.md) — раздел про
  `tool_declarations` дополняется стратегиями; добавляются `capabilities`,
  `lexicon` и шаг «прогнать `lint-profile`» перед первым аудитом.
* [`adapters_and_formats.md`](adapters_and_formats.md) — строка `source_snapshot`
  уточняется: не «ast-скан деклараций `@…tool`», а «объявления по стратегии из
  профиля».
* [`auditor.md`](auditor.md) — команда `lint-profile` и её коды возврата.
