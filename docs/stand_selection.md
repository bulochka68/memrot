# Выбор второго стенда для подключения аудитора

Документ отвечает на два вопроса: **что технически означает «подключить `mcp_audit`
к чужому стенду»** (по коду, а не по описанию) и **какой из десяти найденных
проектов подходит для этого лучше всего**.

Базовая инструкция — [`porting_to_a_new_stand.md`](porting_to_a_new_stand.md).
Здесь — ограничения, которые из неё не видны, и сравнение кандидатов.

---

## 1. Что именно требуется от цели

### 1.1 Лестница покрытия (перепроверена запуском)

```python
from mcp_audit.control_rules.catalog import plan
plan(["source_snapshot", "policy_snapshot", ...])
```

| Набор источников | planned | Что остаётся `not_evaluated` |
|---|---|---|
| только `mcp_inventory` | 5/28 | все MEM, AUTH, INFRA, TOOL-01/04, EGRESS-02, INV-01 |
| `+ source_snapshot` | 21/28 | MEM-08, MEM-10, INFRA-01…03, TOOL-01, EGRESS-02 |
| `+ policy_snapshot` | 24/28 | INFRA-02, INFRA-03, TOOL-01, EGRESS-02 |
| `+ deployment` | 25/28 | INFRA-03, TOOL-01, EGRESS-02 |
| `+ control_fixtures` | 27/28 | TOOL-01 |
| `+ baseline` | 28/28 | — |
| **без `source_snapshot`** (цель не на Python) | 23/28 | MEM-10, AUTH-01, AUTH-03, AUTH-04, AUTH-05 |

Вывод тот же, что в инструкции: всё держится на `source_snapshot`. Но важнее то,
что за числом `planned` скрывается второй фильтр — **применимость**.

### 1.2 Применимость: `planned` ≠ «правило что-то проверит»

`mcp_audit/control_rules/memory_rules.py`:

* строка 23 — `NOT_APPLICABLE, "no memory types declared by profile or policy"`
  → у цели без долговременной памяти **все 10 правил MEM выключаются**;
* строка 32 — `NOT_APPLICABLE, "no shared-audience memory type is declared"`
  → без общей (shared) памяти выключаются правила о публикации политики.

Аналогично `infra_rules.py:147` и `tool_rules.py:285` требуют режим
`controlled_validation`. То есть цель без памяти даёт 26/28 `planned` и при этом
10 правил в статусе `NOT_APPLICABLE` — отчёт формально полный, содержательно пустой.

**Отсюда главный критерий отбора: у цели должны быть одновременно долговременная
память и разделение субъектов.** Это ядро аудитора — 16 правил из 28 (MEM-01…10 +
AUTH-01…06).

### 1.3 Жёсткие ограничения движка (из кода)

| Ограничение | Где | Следствие для выбора цели |
|---|---|---|
| AST разбирается **только для `.py`**: `tree = ast.parse(text) if rel.endswith(".py") else ast.Module(body=[])` | `adapters/source_snapshot.py:102` | цель на JS/TS: `tool_declarations` всегда пуст, `symbol` не находится |
| при `symbol: null` тело = весь файл (`SourceScanner.symbol`, строка 122) | там же | не-Python цель аудируется, но улика — файл целиком, без номеров строк символа |
| `tool_declarations` ищет **декоратор** | `source_snapshot.py:142` | цель, где инструменты — объекты/классы (`Tool(...)`, `class X(BaseTool)`), даёт пустой `source_defined`-инвентарь → INV-01 и TOOL-02 теряют половину входа |
| `deployment` принимает и compose, и JSON-снимок | `adapters/deployment.py` | отсутствие `docker-compose.yml` не блокер: снимок пишется руками |
| runtime-канал = `openai_compat` (HTTP) или `callable` (in-process) | `mcp_attack/adapters/` | цель без HTTP API подключается через `CallableAdapter`, но не через JSON-конфиг — только кодом |

### 1.4 Что пишется руками на каждый стенд

Профиль (`profiles/<стенд>.json`), политика, манифест — руками;
`source_facts` и baseline генерируются; движок не трогается.
Плюс, если нужен runtime, — один адаптер на 40–100 строк.

---

## 2. Кандидаты

Все репозитории склонированы и просмотрены (глубина 1, сентябрь 2026).

| № | Проект | Коммит | Python / JS-TS | Долговр. память | Субъекты + авторизация | MCP | compose | Runtime-канал |
|---|---|---|---|---|---|---|---|---|
| 1 | [ASB](https://github.com/agiresearch/ASB) | `1f561dc` | 124 / 0 | Chroma, **без владельца** | нет | нет | нет | in-process |
| 2 | [damn-vulnerable-ai-agent](https://github.com/opena2a-org/damn-vulnerable-ai-agent) | `faf3fb1` | 9 / **139** | нет (симулятор) | нет в py-части | в JS | 15 | HTTP |
| 3 | [damn-vulnerable-llm-agent](https://github.com/ReversecLabs/damn-vulnerable-llm-agent) | `c0cf9a1` | 4 / 0 | нет (сессия Streamlit) | **4 юзера, реальный BAC** | нет | нет | только Streamlit UI |
| 4 | [agent-memory-redteam](https://github.com/mrmenon23/agent-memory-redteam) | `6605a72` | 79 / 0 | **FAISS, persistent, с метаданными** | нет | нет | нет | in-process (`callable`) |
| 5 | [AgentDojo](https://github.com/ethz-spylab/agentdojo) | `089ed468` | 122 / 0 | нет | нет | нет | нет | in-process |
| 6 | [MCPGoat](https://github.com/sabyasachidhal/MCPGoat) | `80ceaf7` | **0 / 11 (TS)** | нет | есть | настоящий | есть | HTTP/MCP |
| 7 | memory-integrity-benchmark | — | **репозиторий не найден** | — | — | — | — | — |
| 8 | [AgentPoison](https://github.com/BillChan226/AgentPoison) | `7236bf4` | 140 / 0 | RAG-база | нет | нет | нет | in-process |
| 9 | [MINJA](https://github.com/dsh3n77/MINJA) | `a3ec8da` | 36 / 0 | память агента (EHR/QA/rap) | нет | нет | нет | in-process |
| 10 | [InjecAgent](https://github.com/uiuc-kang-lab/InjecAgent) | `f19c9f2` | 9 / 0 | нет | нет | нет | нет | dataset-runner |
| — | [damn-vulnerable-MCP-server](https://github.com/harishsg993010/damn-vulnerable-MCP-server) *(не из списка)* | `79734c1` | 31 / 0 | нет | частично | **FastMCP + SSE** | нет | HTTP/MCP |

Две поправки к исходному списку:

* **№6 MCPGoat написан на TypeScript** (11 `.ts`, 0 `.py`). Для слоя `mcp-invest`
  он бесполезен как цель `source_snapshot`. Питоновский эквивалент с настоящим
  FastMCP — `harishsg993010/damn-vulnerable-MCP-server`, добавлен в таблицу.
* **№7 memory-integrity-benchmark найти не удалось** ни поиском, ни перебором
  вероятных владельцев. Пока считаем, что репозитория нет.

### Почему отпадают крупные бенчмарки (1, 5, 8, 9, 10)

ASB, AgentDojo, AgentPoison, MINJA, InjecAgent — это батч-раннеры, а не стенды.
Нет сервисов → `deployment` пустой, INFRA-01/02 не о чем спросить; нет субъектов →
6 правил AUTH выключены; инструменты объявлены классами (`class TopSeriesAPI(BaseRapidAPITool)`)
→ AST-скан по декоратору ничего не найдёт. У ASB память — один общий
Chroma-стор (`react_agent_attack.py:78`, `similarity_search_with_score`) без
владельца и происхождения, то есть MEM-03/05/06 проверять не на чем.

### Почему отпадает DVAA (№2)

Заявленный набор сценариев идеален (memory injection, cross-session persistence,
BAC, exfiltration), но платформа — 13 300 строк JavaScript, причём ядро называется
`src/core/llm-simulator.js`. Python-файлы (9 штук) — изолированные примеры сценариев.
При JS-цели `source_snapshot` теряет `tool_declarations` и символьные локаторы:
останутся регулярки по файлу целиком. Это ровно тот случай, который аудитор
позволяет, но на котором его нечем показать.

---

## 3. Рекомендация

### Основная цель — `mrmenon23/agent-memory-redteam`, слой `finance_poisoning`

Причины, по пунктам критериев из §1:

1. **Python целиком** (79 файлов) → `source_snapshot` работает на полную, 21 правило.
2. **Настоящая долговременная память** — FAISS-стор с `ingest` / `query`
   (`env/memory_store.py:136,144`) и корпусом на диске. MEM-* становятся
   *применимыми*, а не `NOT_APPLICABLE`.
3. **Есть модель происхождения и доверия**, а это редкость:
   `finance_poisoning/env/schemas.py` содержит `MemorySourceType`
   (`user_note`, `assistant_summary`, `transaction_summary`, `support_chat_note`)
   и `ConfidenceLevel` (low/medium/high). Это прямо ложится на
   `memory_field_map` / `authority` / `derived` профиля и делает
   осмысленными MEM-05 (сохранение происхождения) и MEM-06 (отсутствие
   автоматического повышения доверия).
4. **Домен совпадает с нашим** — финансы/транзакции, и атака та же
   двухфазная: запись сейчас, срабатывание на чужом запросе позже. Наш каталог
   `mcp_attack/catalog/prompts/mem01_03_cross_session_semantic_poisoning` и
   `mem02_global_policy_poisoning` переносится почти без изменений.
5. **Runtime подключается дёшево**: `Agent.act(query, retrieved)` — обычный
   вызываемый объект, `CallableAdapter(send_fn=…)` уже есть в `mcp_attack`.
   Больше того, `MemoryStore.query` даёт `inspect_fn` — белоящичное чтение памяти,
   то есть детекторы получают объективный сигнал, а не текст ответа модели.
6. **`memory_event_snapshot` выгружается напрямую** из `MemoryStore._entries`
   → находки MEM переходят из `static_supported` в `runtime_supported`
   и заполняются стадии W/R/C/B.

Ожидаемый результат: **26/28 `planned`** (не оцениваются `TOOL-01` — нет
`mcp_inventory`+baseline, и `INV-02` — нет MCP), из них 10 правил MEM — применимые.

Конкретные зацепки для профиля (проверены по коду):

| Что пишем | Символ цели | Правила |
|---|---|---|
| `memory_write` | `MemoryStore.ingest` — принимает произвольный `text` + `metadata`, без писателя и аудитории | MEM-02, MEM-03 |
| `memory_read` | `MemoryStore.query` — только `text, k`, фильтра по субъекту нет | MEM-01, MEM-07 |
| `context_include` | `Agent.build_user_message` / `_format_memories` — записи вставляются как `[1] {text}` без разделителя данных и инструкций | **MEM-04** |
| `derivation` | `MemorySourceType.ASSISTANT_SUMMARY` | MEM-05 |
| `trust_elevation` / `security_mode` | `env/defenses.py` | MEM-06 |
| `transmit` | `env/llm_client.py`, `Agent.act` → внешний OpenAI-совместимый эндпоинт | EGRESS-01 |
| `tool_declarations` / `side_effects` | `FinanceTools`, `_assert_read_only_tools` | TOOL-02, TOOL-04 |

Слабые места, которые нужно назвать в отчёте честно:
нет MCP (5 правил недоступны через `mcp_inventory`, но TOOL-02/03/05 и EGRESS-01
берутся из `source_snapshot`), нет субъектов (AUTH-* дадут либо находку
«идентичность отсутствует», либо `NOT_APPLICABLE`), нет compose —
`deployment` пишем JSON-снимком одного процесса и файла индекса.

### Дешёвая разминка — `ReversecLabs/damn-vulnerable-llm-agent`

350 строк, 4 файла. Берётся не вместо основной цели, а перед ней — за пару часов
проверить, что связка «профиль → source-snapshot → audit → validate» работает на
чужом коде. Даёт то, чего нет у основной цели: **реальные находки AUTH**.
`tools.py:get_current_user` жёстко возвращает `db.get_user(1)` (AUTH-01),
`get_transactions(userId)` не проверяет владельца (AUTH-02), политика живёт в
системном промпте `main.py:system_msg` и снимается инъекцией (AUTH-03),
Observation-инъекция → TOOL-04. Памяти нет — 10 правил MEM честно уйдут в
`NOT_APPLICABLE`.

Вместе две цели закрывают обе половины ядра: DVLA — AUTH, agent-memory-redteam — MEM.

### Если позже понадобится MCP-контур

`harishsg993010/damn-vulnerable-MCP-server`: Python + `FastMCP` + SSE
(`@self.mcp.tool()` в 22 файлах). Это единственный найденный способ отработать
`mcp_inventory`-ветку (INV-02, TOOL-01/03/05, EGRESS-01) на чужом коде.

---

## 4. Порядок работ

1. `profiles/dvla.json` + `dvla.policy.json` + `dvla.manifest.json`, прогон
   `source-snapshot` → `audit` → `validate`. Цель шага — убедиться, что движок
   не трогаем.
2. `profiles/agent_memory_redteam.json`: компоненты, `memory_stores`
   (`memory_types` из `MemorySourceType`), `memory_field_map`, `source_facts`
   по таблице выше.
3. `agent_memory_redteam.policy.json` — ожидания: изоляция по субъекту,
   разделение записи и публикации, сохранение происхождения при суммаризации.
4. `deployment` JSON-снимком; офлайн-аудит; разбор `contradicted` / `unknown`.
5. Runtime: `CallableAdapter` поверх `Agent.act` + выгрузка
   `memory_event_snapshot` из `MemoryStore`; повторный прогон — часть находок
   поднимается до `runtime_supported`.
6. Тест по образцу `tests/test_rest_native_profile.py`, фикстуры в `tests/fixtures/`.
