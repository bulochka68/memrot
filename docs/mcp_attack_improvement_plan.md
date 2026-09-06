# План развития `mcp_attack`: контракты фич и функций для кодинг-агента

**Назначение.** Технический план доработки red-team-харнесса `mcp_attack` (и его стыка с `mcp_audit`)
до состояния «удобный инструмент, которым максимально легко тестировать любого агента в любом режиме».
Документ разбирает текущий код по шести требованиям заказчика, фиксирует разрывы и задаёт **чёткий
контракт на каждую новую/изменяемую функцию** — так, чтобы кодинг-агент реализовал недостающее без
додумывания.

**Метод.** Статический разбор ветки. Стенд, MCP-процессы и модель не запускались. Номера строк и
имена — по текущему рабочему дереву репозитория (`mcp_attack/`, `mcp_audit/`, `examples/`, `docs/`,
`tests/`). Все контракты — аддитивные: существующие CLI-флаги, конфиги и тесты должны продолжать
работать (обратная совместимость — явное требование в `audit_bridge.py`/`audit_plan.py`).

---

## 0. Итоговая оценка по требованиям (scorecard)

| # | Требование | Статус | Ключевой разрыв |
|---|---|---|---|
| 1 | Атаки вызываются в порядке ранжирования аудитором | 🟡 частично | `ranked`-режим есть, но не является дефолтом; bridge-таблица `rule_id→category` частична; нет `--top-N`/строгого приоритета; не используется `downstream.P3_corpus` аудита |
| 2 | Широкие классы промптов; максимум техник; таксономия у **всех** | 🔴 разрыв | 22 из 45 статических вариантов **без** `owasp_amg_category`; ATLAS покрывает лишь 2 id; нет целых классов техник (obfuscation/encoding, many-shot, payload-splitting, unicode, code-injection) |
| 3 | Indirect через тулы (email, web-search…) влияют на память | 🟡 частично | реализован только web-search и только против in-process стенда; `document_ingestion` объявлен, но не реализован; нет email/иных векторов; чёрный ящик недоступен |
| 4 | Независимость от стенда; любой агент, white/black-box | 🟡 частично | generic black-box (`openai_compat`) есть; но tool-staging/инспекция памяти/ground-truth — только стенд; нет generic MCP-адаптера; нет доки «подключение к новому агенту» |
| 5 | Промпты в базе — нейтральный домен, без привязки к инвест-стенду | 🟡 частично | нейтральные `generic_*` есть, но bank-специфичные пулы (`mem02`, `mem01_03`, `framing_diversity`, `auth_tool`, `benign`) лежат в том же общем каталоге и грузятся демо-конфигом |
| 6 | LLM для адаптации, мутации и **генерации новых** промптов + специфика агента | 🟡 частично | мутация seed→variant есть; **генерации net-new нет**; доменной адаптации под цель нет; адаптивного (PAIR/TAP) цикла по ответу цели нет |

Легенда: 🟢 готово · 🟡 частично · 🔴 разрыв.

**Вывод.** Ядро (движок канареек, вердикты, отчётность, ASR-агрегация, tracer) — зрелое и его трогать
не нужно. Работа сосредоточена в четырёх плоскостях: **(A) каталог и таксономия**, **(B) адаптеры и
векторы доставки**, **(C) LLM-генерация/адаптация**, **(D) UX: CLI одной командой + аудит→атака +
нотбук**.

---

## 1. Что уже есть (база, которую не ломаем)

- **Движок** `runner/engine.py`: 4-фазный поток канарейки (baseline→inject→consolidate→probe) для
  `cross-user`/`cross-session-same-user`; одноходовой поток для `single-turn`; отдельный
  `tool_result`-поток (baseline→stage→trigger→consolidate→probe). Любой сбой адаптера → `ERROR`,
  недостаток возможностей адаптера → `NOT_EVALUATED`, никогда не молчаливый `CLEAN`.
- **Модель данных** `models.py`: `AttackVariant`, `AttackResult`, `Verdict` (CONFIRMED/CLEAN/INVALID/
  ERROR/NOT_EVALUATED), `GroupMetric` («n/a (0/0)» вместо выдуманного процента), `RunReport`.
- **Контракт адаптера** `adapters/base.py`: `new_session`/`send` обязательны; `consolidate`,
  `inspect_memory`, `ground_truth_check`, `reset`, `stage_tool_response`, `capabilities` — опциональны
  с безопасными no-op. Это и есть точка «универсальное ядро + тонкий адаптер».
- **Адаптеры**: `openai_compat` (generic black-box, stdlib-only), `genai_invest` (стенд, +finalize,
  +white-box Mongo/Redis, +ground-truth по docker-логам), `callable` (in-code), `inprocess_stand`
  (grey-box, монкипатч `DDGS`).
- **Каталог**: `catalog/prompts/*/catalog.json` (валидатор `catalog/schema.py`, загрузчик
  `catalog/loader.py`); импортированные банки garak DAN (Apache-2.0) и TrustAIRLab (MIT).
- **Мутации** `mutation/techniques.py`: 5 детерминированных (prefix_injection, base64_obfuscation,
  persona_override, state_toggle_override, forced_output_shape) + 4 LLM (paraphrase, roleplay_framing,
  translation, escalation_rewrite). `LLMClient` — единый OpenAI-совместимый клиент.
- **Детекторы** `detectors/`: literal, ground_truth, llm_judge (деградирует до literal при сбое).
- **Стык с аудитом**: `audit_bridge.py` (filter/prioritize по `rule_id`) и `audit_plan.py`
  (`ranked` по severity с bridge `rule_id→owasp_amg_category`).
- **Отчётность**: `reporting/emitter.py` (JSON/MD), `reporting/html_emitter.py`, `reporting/aggregate.py`
  (ASR по осям/rule_id/taxonomy/mutation/threat_model), `tracer.py` (JSONL, фрагмент+sha256).
- **CLI** `cli.py`: `run`, `list-catalog`, `validate-catalog`.

Инварианты, которые обязаны сохраниться после всех правок (регресс-барьер):

1. Ни один attempt не исчезает: у каждого — `Verdict`.
2. Знаменатель ASR не подделывается: `total==0 → "n/a (0/0)"`.
3. `INVALID`/`ERROR`/`NOT_EVALUATED` исключены из ASR-ratio, но видны в `counts_by_verdict`.
4. `mcp_attack` не импортирует `mcp_audit` (связь — только через JSON и строковые теги).
5. Секреты не встраиваются в конфиг: только `credential_ref` → `MCP_ATTACK_CRED_<ref>`.
6. Black-box-путь не тянет сторонних HTTP/SDK-зависимостей (stdlib `urllib`).

---

## 2. Плоскость A — Каталог и таксономия

### A0. Проблема
- **22/45 вариантов без `owasp_amg_category`** (проверено: `bac-*`, `benign-*`, `framing-*`, `mem03-*`,
  `mem02-*`). Требование «для всех техник проставлена актуальная таксономия» нарушено.
- **ATLAS-таксономия тонкая**: реально используются только `AML.T0051` и `AML.T0070`. Целых классов
  техник в каталоге нет.
- **Смешение доменов**: нейтральные `generic_*` и bank-специфичные пулы лежат вперемешку.

### A1. Обязательная таксономия у каждого варианта (валидатор)
**Файл:** `mcp_attack/catalog/schema.py`, `mcp_attack/taxonomy.py`.

**Контракт `taxonomy.py` (расширение словаря).**
- Добавить второй, независимый реестр `ATTACK_TECHNIQUE_CATEGORIES: Dict[str, TechniqueCategory]` для
  техник **доставки/обфускации** (то, что не покрывают 6 memory-focused AMG-категорий), с полями:
  ```python
  @dataclass(frozen=True)
  class TechniqueCategory:
      slug: str                    # 'obfuscation_encoding', 'many_shot', 'payload_splitting', ...
      title: str
      owasp_llm_id: str            # OWASP LLM Top-10 2025, обычно 'LLM01' (Prompt Injection)
      atlas_technique_ids: Tuple[str, ...]   # напр. ('AML.T0051.000',)
      description: str
  ```
  Минимальный набор slug'ов (расширяемый): `direct_instruction_override`, `authority_impersonation`,
  `obfuscation_encoding`, `payload_splitting`, `many_shot`, `refusal_suppression`,
  `roleplay_persona`, `low_resource_language`, `tool_result_injection`, `context_ignore`.
- Функция `technique_category(slug) -> TechniqueCategory` и `is_known_technique(slug) -> bool` —
  зеркально существующим `category()`/`is_known_category()`.
- **Не удалять** и не переименовывать существующие `OWASP_AMG_CATEGORIES` — только дополнить.

**Контракт `schema.py` (ужесточение валидации, с грейс-периодом).**
- Ввести уровень строгости: `validate_catalog_file(path, *, require_taxonomy: bool = False)`.
- При `require_taxonomy=True`: каждый вариант с `threat_model="memory_poisoning"` обязан иметь
  непустой `owasp_amg_category` из `OWASP_AMG_CATEGORY_SLUGS`; каждый вариант обязан иметь непустой
  `taxonomy` (ATLAS) **или** новый `technique_category` (см. A2). `benign_control`-варианты
  освобождаются (у них `framing='none'`/`payload='none'` — уже распознаётся).
- Дефолт `require_taxonomy=False`, чтобы старые тесты не падали; CLI `validate-catalog` получает флаг
  `--strict-taxonomy`, а `run`/`list-catalog` — нет.
- Ошибка формулируется как: `"{where}: memory_poisoning variant must carry owasp_amg_category"`.

**Definition of done:** `python -m mcp_attack validate-catalog mcp_attack/catalog/prompts --strict-taxonomy`
даёт 0 ошибок; юнит-тест `test_attack_taxonomy.py` проверяет, что во всём дефолтном каталоге нет
memory-варианта без AMG-категории.

### A2. Новое поле `technique_category` на `AttackVariant`
**Файл:** `mcp_attack/models.py`.

**Контракт.**
- Добавить поле `technique_category: str = ""` в `AttackVariant` (рядом с `owasp_amg_category`), с
  комментарием-ссылкой на `taxonomy.ATTACK_TECHNIQUE_CATEGORIES`.
- Прокинуть в `AttackResult` (новое поле `technique_category: str = ""`) и в `to_dict()`.
- Загрузчик `catalog/loader.py`: читать `v.get("technique_category", "")`.
- Мутации `mutation/techniques.py`: `_replace_payload` проставляет `technique_category` = slug из
  маппинга «техника мутации → категория» (например `base64_obfuscation → obfuscation_encoding`,
  `persona_override/roleplay_framing → roleplay_persona`, `escalation_rewrite → many_shot`), чтобы
  сгенерированный вариант **автоматически** получал таксономию.
- Агрегатор `reporting/aggregate.py`: добавить `asr_by_technique_category` (зеркально
  `asr_by_taxonomy_category`), прокинуть в `RunReport.to_dict()` и MD/HTML-эмиттеры.

**Обратная совместимость:** поле опциональное со значением `""`; отсутствие в JSON не ломает загрузку.

### A3. Разделение каталога: нейтральное ядро vs доменный оверлей
**Каталог:** `mcp_attack/catalog/prompts/`.

**Контракт (перекладка файлов + метка).**
- Ввести подкаталоги-неймспейсы:
  - `catalog/prompts/generic/` — **нейтральное ядро** (перенести сюда все `generic_*`). Никакой
    доменной лексики: только «assistant / user / system».
  - `catalog/prompts/domain/invest_bank/` — доменный оверлей стенда (перенести `mem02_*`,
    `mem01_03_*`, `framing_diversity`, `auth_tool_direct_bac_injection`, `benign_control`).
- В каждый `catalog.json` добавить в корень поле `"domain": "neutral" | "invest_bank"` (по умолчанию
  `"neutral"`). Загрузчик кладёт его в `AttackVariant.notes`-мета или новое поле `domain: str = "neutral"`
  (предпочтительно отдельное поле — оно нужно для CLI-фильтра, см. D2).
- `discover_catalog_files` уже рекурсивен — перекладка не ломает загрузку по родительскому пути.
- **Совместимость путей:** старые пути в `examples/genai_invest_stand.attack.config.json` и в нотбуках
  обновить на новые; добавить в `docs/` таблицу «старый путь → новый путь».

**Definition of done:** `list-catalog --catalog mcp_attack/catalog/prompts/generic` не содержит ни
одного слова из доменного стоп-листа (`портфель|клиент|invest|portfolio|bank|cus|1001..1005`) —
добавить тест `test_neutral_pool_has_no_domain_words`.

### A4. Расширение классов техник (новые нейтральные пулы)
**Каталог:** `catalog/prompts/generic/`.

**Контракт (новые `catalog.json`, каждый вариант с полной таксономией).** Добавить по одному пулу на
класс, каждый — 2–4 варианта, `domain: "neutral"`, `technique_category` проставлен, `taxonomy` (ATLAS)
и/или `owasp_amg_category` заданы:

| Пул (folder) | technique_category | Что проверяет |
|---|---|---|
| `generic_obfuscation_encoding` | `obfuscation_encoding` | инъекция через base64/rot13/hex/unicode-escape в память |
| `generic_payload_splitting` | `payload_splitting` | payload, собираемый из нескольких «безобидных» частей |
| `generic_many_shot` | `many_shot` | many-shot прайминг (длинный псевдодиалог, узаконивающий правило) |
| `generic_refusal_suppression` | `refusal_suppression` | подавление отказов/дисклеймеров как стойкое правило |
| `generic_context_ignore` | `context_ignore` | «ignore previous instructions»-класс, персистируемый в память |
| `generic_low_resource_language` | `low_resource_language` | тот же payload на редком языке (обход keyword-фильтров) |

Замечание по канарейке: для обфускации маркер `{canary}` **обязан оставаться в открытом виде** после
кодированной части (см. существующий комментарий в `Base64ObfuscationTechnique` — `_safe_format`
подставляет только видимый `{canary}`). Валидатор A1 уже это ловит через проверку `{canary}` в шаблоне.

**Definition of done:** `list-catalog` показывает ≥ 6 новых нейтральных пулов; у каждого варианта
непустые `technique_category` + (`taxonomy` или `owasp_amg_category`).

---

## 3. Плоскость B — Адаптеры и векторы доставки (независимость + любой агент)

### B0. Проблема
- `stage_tool_response` (indirect-инъекция) реализован только у `inprocess_stand` (стенд).
- `document_ingestion` объявлен в `DELIVERY_CHANNEL_VALUES`, но движок его не исполняет.
- Реестр адаптеров (`adapters/registry.py`) знает только `openai_compat` и `genai_invest`.
- Нет generic-способа сделать indirect-инъекцию против произвольного чёрного ящика.

### B1. Обобщённый tool-vector контракт: `stage_tool_response` с именем вектора
**Файл:** `adapters/base.py`, `runner/engine.py`, `models.py`.

**Контракт (расширение сигнатуры, обратно совместимо).**
- Расширить метод адаптера:
  ```python
  def stage_tool_response(self, tool_name: str, content: str, *, vector: str = "web_search") -> None
  ```
  `vector ∈ {"web_search", "email", "document", "calendar", "crm", "custom"}` — семантический ярлык
  канала доставки; адаптер сам решает, как смоделировать (какой инструмент вернёт `content`). Дефолт
  сохраняет текущее поведение.
- `AttackVariant.tool_stage` расширяется до `{"tool_name": ..., "content_template": ..., "vector": ...}`
  (поле `vector` опционально, дефолт `"web_search"`). Валидатор `schema.py` принимает `vector` из
  разрешённого множества.
- `AdapterCapabilities` получает `supported_tool_vectors: List[str] = field(default_factory=lambda: [])`.
  Движок в `_run_tool_injection_flow`: если `variant.tool_stage.vector` не в
  `caps.supported_tool_vectors` (и при этом `supports_tool_staging`), вернуть `NOT_EVALUATED` с
  внятным `limitations`, а не пытаться и не выдавать ложный `CLEAN`.
- Новые нейтральные пулы `generic_tool_email_injection`, `generic_tool_document_injection` (см. B4).

**Definition of done:** движок корректно раздаёт `NOT_EVALUATED`, когда адаптер не поддерживает вектор;
тест `test_attack_tool_injection_flow.py` расширен кейсом «vector не поддержан».

### B2. Реализация `document_ingestion` в движке
**Файл:** `runner/engine.py`.

**Контракт.**
- Добавить `_run_document_ingestion_flow(...)` — структурно как `_run_tool_injection_flow`, но payload
  подаётся не как tool-result, а как **вложение/документ в пользовательском ходе** (RAG-подобный
  сценарий): baseline → (victim отправляет ход, содержащий/ссылающийся на отравленный документ) →
  consolidate → probe. Требует у адаптера `capabilities().supports_document_ingestion` (новое булево);
  иначе `NOT_EVALUATED`.
- Диспетчер в `run_variant`: `if variant.delivery_channel == "document_ingestion": return _run_document_ingestion_flow(...)`.
- Метод адаптера (опциональный, no-op по умолчанию):
  ```python
  def ingest_document(self, principal: Principal, session_id: str, document_text: str) -> str:
      """Подать документ так, как его получил бы агент (вложение/RAG-контекст);
      вернуть ответ ассистента. No-op default → supports_document_ingestion=False."""
  ```

**Definition of done:** есть тест на `CallableAdapter` с `ingest_document`-хуком, показывающий
CONFIRMED/CLEAN; без хука — `NOT_EVALUATED`.

### B3. Generic-адаптеры для «любого агента»
**Файл:** `adapters/`.

**B3.1 `mcp_client` адаптер (grey-box, MCP-агенты).**
- Новый `adapters/mcp_client.py`, класс `MCPClientAdapter(TargetAdapter)`, `kind="mcp_client"`.
- Конструктор: `base_url`/`command` (streamable-HTTP или stdio MCP-сервер), список инструментов
  обнаруживается через MCP-handshake (переиспользовать логику `mcp_audit.discovery.introspector` **как
  референс**, но не импортировать — скопировать минимальный клиент или вынести в отдельный stdlib-модуль).
- Реализует `send` как «вызвать инструмент чата/агента»; `stage_tool_response` — через подмену
  ответа конкретного инструмента, если сервер это позволяет; иначе `supports_tool_staging=False`.
- Регистрируется в `adapters/registry.py`.

**B3.2 Явный generic white-box контракт + пример.**
- `CallableAdapter` уже даёт in-code white-box путь. Нужно **документировать его как основной способ
  подключить произвольную память-библиотеку** (mem0, LangGraph, кастомный SDK): в `docs/attacker.md`
  (см. D4) — раздел «Подключение нового агента за 40 строк» с примером, где `inspect_fn`/`reset_fn`/
  `stage_tool_fn` замыкаются на API целевой библиотеки.
- Добавить `adapters/registry.py`-запись `"http_generic"` — тонкий подкласс `OpenAICompatAdapter` с
  настраиваемым мэппингом полей запроса/ответа (`response_path`, `messages_field`,
  `session_in_body`), чтобы не-OpenAI-совместимый HTTP-агент подключался конфигом, а не кодом.

**Definition of done:** `build_adapter` строит `mcp_client`/`http_generic` из JSON-конфига; тест
`test_adapters.py` (attack-часть) покрывает конструкцию каждого нового `kind`.

### B4. Новые нейтральные indirect-пулы
**Каталог:** `catalog/prompts/generic/`.

**Контракт.** Добавить (все `domain: "neutral"`, `owasp_amg_category="tool_output_instruction_injection"`,
`technique_category="tool_result_injection"`, `taxonomy=["AML.T0070"]`):
- `generic_tool_email_injection` — payload в теле «входящего письма», которое агент читает
  инструментом чтения почты; `tool_stage.vector="email"`.
- `generic_tool_document_injection` — payload в теле документа (`delivery_channel="document_ingestion"`).
- Обобщить существующий `tool_output_web_search_poisoning`: вынести нейтральную копию в
  `generic/generic_tool_websearch_injection` (без инвест-лексики), а доменную оставить в
  `domain/invest_bank/`.

---

## 4. Плоскость C — LLM-генерация, адаптация, адаптивный цикл (требование 6)

### C0. Проблема
- Есть только мутация seed→variant. Нет (а) генерации net-new промптов, (б) доменной адаптации под
  цель, (в) адаптивного цикла, использующего ответ цели.

### C1. Доменная адаптация нейтрального промпта под цель
**Файл:** `mutation/techniques.py`, `mutation/domain.py` (новый).

**Контракт.**
- Новый класс `DomainAdaptationTechnique(MutationTechnique)`, `slug="domain_adaptation"`,
  `requires_llm=True`.
- Конструктор принимает `domain_profile: DomainProfile` — лёгкую структуру:
  ```python
  @dataclass
  class DomainProfile:
      domain: str                    # 'investment banking', 'healthcare triage', ...
      persona: str = ""              # как агент себя называет
      example_entities: List[str] = field(default_factory=list)  # тикеры, id счетов и т.п.
      tool_names: List[str] = field(default_factory=list)        # обнаруженные инструменты цели
  ```
- `_mutate_texts` просит LLM переписать нейтральный payload в лексике `domain`, **сохранив
  `{canary}`/маркер дословно** (тот же системный промпт-инвариант, что у прочих LLM-техник; проверка
  `_replace_payload` на потерю маркера уже есть).
- Источник `DomainProfile`: (1) вручную в конфиге (`generator.options.domain_profile`), (2)
  авто-извлечение из отчёта `mcp_audit` (`components`/`capabilities`/tool-имена) — функция
  `domain.profile_from_audit(audit_path) -> DomainProfile` (чистый JSON-парсинг, без импорта mcp_audit).

**Definition of done:** тест с фейковым `LLMClient`, показывающий, что нейтральный вариант получает
доменную лексику и сохраняет маркер; при потере маркера в `notes` появляется предупреждение.

### C2. Генерация net-new промптов (не только мутация seed)
**Файл:** `catalog/generator.py`.

**Контракт.**
- Новый `LLMSynthesisGenerator(AttackGenerator)`, `kind="llm_synthesis"`.
- Конструктор: `llm: LLMClient`, `spec: SynthesisSpec`, где
  ```python
  @dataclass
  class SynthesisSpec:
      owasp_amg_category: str        # какую категорию генерируем
      technique_category: str = ""
      framing: str = "explicit_rule"
      propagation: str = "cross-user"
      n: int = 3                     # сколько вариантов
      domain_profile: Optional[DomainProfile] = None
  ```
- `generate()` вызывает LLM с рубрикой (system-prompt требует: вернуть JSON-массив объектов формата
  `AttackVariant`-подмножества — `title`, `inject_turns`/`probe`, `canary_template` с `{canary}`), затем
  **прогоняет каждый через `validate_variant_dict`** и отбрасывает невалидные (как и
  `LLMMutationGenerator`, единичный сбой не рушит генерацию). Категорию/таксономию проставляет из `spec`.
- Каждому сгенерированному варианту: `source="llm_synthesis"`, `id=f"synth-{category}-{hash8}"`.
- **Безопасность знаменателя:** сгенерированные варианты помечаются `source`, чтобы отчёт мог показать
  ASR отдельно «синтезированные vs курируемые» (добавить `asr_by_source` в агрегатор — по аналогии с
  `asr_by_mutation_technique`).

**Definition of done:** тест с фейковым LLM, возвращающим 3 объекта (2 валидных, 1 битый) → на выходе
2 валидных `AttackVariant` с корректной таксономией.

### C3. Адаптивный цикл (PAIR/TAP-lite) по ответу цели
**Файл:** `runner/adaptive.py` (новый), `cli.py`.

**Контракт (отдельный, необязательный слой над движком — ядро не трогаем).**
- Функция:
  ```python
  def run_adaptive(seed: AttackVariant, channels, adapter, detector, tracer, run_id, *,
                   attacker_llm: LLMClient, max_rounds: int = 3,
                   technique_slugs: Sequence[str] = ("paraphrase", "roleplay_framing")
                   ) -> List[AttackResult]:
      """Итеративно: выполнить вариант через существующий run_variant; если verdict != CONFIRMED,
      отдать attacker_llm (payload, ответ цели из tracer) и попросить улучшенный payload; повторить
      до CONFIRMED или max_rounds. Вернуть ВСЕ раунды как отдельные AttackResult (каждый со своим
      verdict) — ничего не скрываем."""
  ```
- Использует **только** публичные методы движка/детектора/tracer; не меняет `run_variant`.
- Каждый раунд — самостоятельный `AttackResult` с пометкой `mutation_technique="adaptive_round_{k}"`,
  чтобы ASR-агрегатор без изменений показал прогресс по раундам.
- CLI: `run --adaptive --adaptive-max-rounds N --attacker-base-url ... --attacker-model ...`. Требует
  сконфигурированного attacker-LLM; при отсутствии — `EXIT_ERROR` с внятным сообщением.
- Стоп-условие и стоимость: жёсткий `max_rounds`, при `ERROR` от адаптера цикл прерывается (раунд
  фиксируется как ERROR).

**Definition of done:** тест с фейковыми adapter+LLM: раунд 1 CLEAN, раунд 2 CONFIRMED → на выходе 2
результата, второй CONFIRMED; при неулучшаемом payload — `max_rounds` результатов, все не-CONFIRMED.

---

## 5. Плоскость D — UX: аудит→атака, CLI одной командой, нотбук

### D1. `ranked` как первоклассный режим аудита-приоритезации
**Файл:** `audit_plan.py`, `cli.py`, `config.py`.

**Контракт.**
- Достроить bridge-таблицу `RULE_ID_TO_OWASP_AMG_CATEGORY`: сейчас `AUTH-*`/`INFRA-*`/`INV-*`/`TOOL-01/02`
  не сопоставлены. Для «tool/BAC»-классов ввести отдельный маппинг **на `technique_category`** (а не
  на AMG-категорию памяти), например `AUTH-02/AUTH-03 → tool_result_injection`/`direct_instruction_override`,
  `TOOL-04/TOOL-05 → tool_result_injection`. Реализовать вторую bridge-таблицу
  `RULE_ID_TO_TECHNIQUE_CATEGORY` и учитывать её в `variant_rank` (кандидат-ранг также по
  `v.technique_category`). Незамапленные rule_id по-прежнему деградируют до прямого `rule_id`-матчинга
  с записью в `limitations` (поведение сохраняется).
- Добавить `select_variants_by_audit(..., top_n: Optional[int] = None)`: при заданном `top_n` **обрезать**
  до N наиболее приоритетных (для «вызываются те атаки в том порядке» с бюджетом). Без `top_n` —
  прежнее поведение (только переупорядочивание, ничего не выкидываем).
- Использовать `audit_doc["downstream"]["P3_corpus"]` как дополнительный сигнал приоритета: если аудит
  сам сгруппировал находки в кампании (C2 memory poisoning, C4-IDOR…), варианты соответствующих
  категорий поднимаются. Реализовать `_campaign_boost(audit_doc) -> Dict[category, int]`; аддитивно к
  severity-рангу.
- `config.py`: дефолт `audit_mode` оставить `"filter"` для совместимости, но в **новом
  quickstart-пути** (D2) использовать `"ranked"`.

**Definition of done:** `test_attack_audit_plan.py` расширить: (а) `top_n` обрезает и сохраняет порядок;
(б) BAC-варианты (`AUTH-02`) стоят выше memory-вариантов при реальном `examples/*.audit.json` (уже так —
закрепить тестом); (в) незамапленные rule_id всё ещё дают `limitations`-заметку.

### D2. CLI одной командой: `mcp_attack quickstart`
**Файл:** `cli.py`.

**Проблема.** Сейчас `run` требует готовый JSON-конфиг (target+channels+catalog). Для «подключить к
любому агенту минимумом команд» нужен путь без ручного конфига.

**Контракт нового субкоманды `quickstart`.**
```
python -m mcp_attack quickstart \
  --url http://localhost:8600/v1 --model my-agent \
  [--adapter openai_compat|genai_invest|mcp_client|http_generic] \
  [--attacker-principal A --victim-principal B] \
  [--cred-attacker-env MCP_ATTACK_CRED_A --cred-victim-env MCP_ATTACK_CRED_B] \
  [--audit path/to/stand.json]   # если задан — режим ranked \
  [--domain "investment banking"]  # включает domain_adaptation, если задан attacker-LLM \
  [--pool neutral|all|<путь>]      # по умолчанию neutral \
  [--out .attack] [--gate] [--report-html .attack/run.html]
```
Поведение:
- Строит `RunConfig` **в памяти** из флагов: target-binding из `--url/--model/--adapter`; два канала
  (attacker/victim) с дефолтными principal_id и credential_ref; `catalog_paths` = нейтральное ядро
  (`catalog/prompts/generic`) при `--pool neutral`.
- Если `--url` не задан — понятная ошибка (`EXIT_ERROR`), а не трейсбек.
- Если `--audit` задан — `audit_mode="ranked"`.
- Если целевых кредов в env нет — **не падать до запуска**: подставить безопасный плейсхолдер и добавить
  `limitations`-заметку «использован placeholder-credential, ответы могут быть 401/anonymous»
  (как в нотбуке `mcp_attack_demo`).
- Дальше — та же `run_matrix` + эмиттеры, что у `run`.
- Ровно один happy-path вызов: `python -m mcp_attack quickstart --url ... --model ...` должен дать
  JSON-статус в stderr и отчёт.

**Определение «минимум команд»:** для чёрного ящика — одна команда `quickstart --url --model`; для
цикла аудит→атака — две (`mcp_audit audit …` затем `mcp_attack quickstart --url --model --audit …`).

**Definition of done:** `test_attack_cli.py` — кейс, что `quickstart` без конфиг-файла собирает
валидный `RunConfig` и отрабатывает против фейкового callable-таргета (через монкипатч `build_adapter`).

### D3. Единый «pipeline»-хелпер аудит→атака
**Файл:** `mcp_attack/pipeline.py` (новый) — тонкая обёртка, без импорта `mcp_audit`.

**Контракт.**
```python
def audit_then_attack(audit_json_path: str, target: TargetBinding, channels: List[Channel], *,
                      pool: str = "neutral", top_n: Optional[int] = None,
                      detector=None, tracer=None, adaptive: bool = False,
                      attacker_llm: Optional[LLMClient] = None) -> RunReport:
    """Загрузить нейтральный пул → ranked-приоритезация по audit_json → run_matrix (или run_adaptive) →
    RunReport. Чистая функция уровня API для нотбука/скриптов; CLI quickstart зовёт её же."""
```
Требование: `quickstart` и нотбук вызывают **одну и ту же** функцию (единый источник истины).

### D4. Документация модуля атак
**Файл:** `docs/attacker.md` (новый, зеркало `docs/auditor.md`), правки `README.md`, `docs/project_overview.md`.

**Контракт содержания `docs/attacker.md`:**
1. Что отвечает харнесс (какие вопросы), таблица режимов/access-profile.
2. Таблица адаптеров: `openai_compat`/`http_generic`/`mcp_client`/`genai_invest`/`callable` — какой
   когда, что даёт (черный/серый/белый ящик, какие каналы детекции).
3. **«Подключить новый агент за 40 строк»** — пример на `CallableAdapter` (white-box, mem0/LangGraph) и
   пример `quickstart` (black-box).
4. Таксономия: OWASP AMG (память) + `technique_category` (доставка/обфускация) + ATLAS + связь с
   `rule_id`-словарём аудита; таблица «источник → сколько классов покрыто».
5. Матрица делать/не-делать: инварианты знаменателя ASR, `NOT_EVALUATED` вместо ложного CLEAN.
6. Перенос пула на новый домен (нейтральное ядро + `domain_adaptation`).
- `README.md`: добавить раздел «Red-team харнесс (`mcp_attack`)» с одной quickstart-командой и ссылкой
  на `docs/attacker.md` (сейчас README про `mcp_attack` не упоминает вовсе).
- `docs/project_overview.md`: добавить `mcp_attack` в карту (сейчас в петле фигурирует только
  `redteam/`, а не `mcp_attack`).

### D5. Нотбук-демонстрация use-case (обновление)
**Файл:** `examples/notebooks/mcp_attack_quickstart.ipynb` (новый, «главный» демо) + правки двух
существующих под новые пути каталога.

**Контракт содержания нового нотбука (линейный, воспроизводимый, ≤ 10 ячеек):**
1. Установка/поиск корня репо (переиспользовать `_find_repo_root` из существующих нотбуков).
2. **Одна команда**: `audit_then_attack(...)` против цели (реальный стенд, если поднят; иначе
   `CallableAdapter`-фолбэк с детерминированной in-memory «памятью», чтобы нотбук проходил и без стенда).
3. Показ ranked-порядка из реального `examples/genai_invest_stand.audit.json`.
4. Прогон нейтрального пула black-box + вывод `report.overall_asr.display` и `counts_by_verdict`.
5. Indirect через тул (email/web-search) на in-process/фолбэк-адаптере.
6. LLM-мутация + `domain_adaptation` (с фейковым/локальным LLM, если ключ есть; иначе ячейка помечена
   «нужен ключ» и пропускается gracefully).
7. HTML-дашборд (`emit_html`) в iframe.
8. «Успех vs провал»: join `report.results` ↔ `tracer.events` по `variant_id` — какой промпт ушёл и
   что агент сделал (переиспользовать блок из `mcp_attack_demo.ipynb`).

**Требование к нотбуку:** проходит **без** поднятого стенда и **без** сетевого LLM (все внешние
зависимости — за флагом/фолбэком), чтобы быть честным «use-case out of the box».

**Definition of done:** `jupyter nbconvert --execute` нового нотбука завершается без ошибок в окружении
без стенда и без ключей (сетевые ячейки — под `try/skip`).

---

## 6. Сводная таблица контрактов (для планировщика задач)

| ID | Файл(ы) | Тип | Обратная совместимость |
|---|---|---|---|
| A1 | `taxonomy.py`, `catalog/schema.py` | реестр техник + `--strict-taxonomy` | ✅ дефолт off |
| A2 | `models.py`, `catalog/loader.py`, `mutation/techniques.py`, `reporting/aggregate.py` | поле `technique_category` + ASR-ось | ✅ поле опционально |
| A3 | `catalog/prompts/**` | перекладка neutral/domain + поле `domain` | ⚠️ обновить пути в конфигах/нотбуках |
| A4 | `catalog/prompts/generic/**` | 6 новых нейтральных пулов | ✅ аддитивно |
| B1 | `adapters/base.py`, `runner/engine.py`, `models.py`, `catalog/schema.py` | `stage_tool_response(vector=...)` + `supported_tool_vectors` | ✅ дефолт `web_search` |
| B2 | `runner/engine.py`, `adapters/base.py` | `document_ingestion`-поток + `ingest_document` | ✅ no-op default → NOT_EVALUATED |
| B3 | `adapters/mcp_client.py`, `adapters/registry.py`, `adapters/openai_compat.py` | адаптеры `mcp_client`, `http_generic` | ✅ аддитивно |
| B4 | `catalog/prompts/generic/**` | email/document/websearch нейтральные пулы | ✅ аддитивно |
| C1 | `mutation/domain.py`, `mutation/techniques.py` | `DomainAdaptationTechnique` + `DomainProfile` | ✅ новая техника |
| C2 | `catalog/generator.py`, `reporting/aggregate.py` | `LLMSynthesisGenerator` + `asr_by_source` | ✅ новый генератор |
| C3 | `runner/adaptive.py`, `cli.py` | `run_adaptive` + `--adaptive` | ✅ отдельный слой |
| D1 | `audit_plan.py`, `cli.py`, `config.py` | bridge-достройка, `top_n`, P3-boost | ✅ прежнее поведение по умолчанию |
| D2 | `cli.py` | субкоманда `quickstart` | ✅ аддитивно |
| D3 | `pipeline.py` | `audit_then_attack` | ✅ новый модуль |
| D4 | `docs/attacker.md`, `README.md`, `docs/project_overview.md` | документация | ✅ |
| D5 | `examples/notebooks/*` | новый quickstart-нотбук + правки путей | ⚠️ пути |

---

## 7. Порядок реализации (рекомендуемые этапы)

**Этап 1 — таксономия и каталог (закрывает требования 2 и 5).** A1 → A2 → A3 → A4. После этого у
каждого варианта есть таксономия, а нейтральное ядро отделено от домена. Низкий риск, высокий эффект,
не трогает движок.

**Этап 2 — UX аудит→атака одной командой (требования 1 и «удобство»).** D1 → D3 → D2 → D5(частично).
Даёт демонстрируемый «минимум команд» и корректный ranked-порядок.

**Этап 3 — векторы доставки (требование 3).** B1 → B2 → B4. Email/document/generic-web-search indirect.

**Этап 4 — независимость/любой агент (требование 4).** B3 (`mcp_client`, `http_generic`) + D4 (доки
подключения нового агента).

**Этап 5 — LLM-генерация/адаптация (требование 6).** C1 → C2 → C3. Замыкается на нейтральное ядро из
этапа 1 и quickstart из этапа 2.

Каждый этап самодостаточен и проходит тесты независимо; ветку можно мержить поэтапно.

---

## 8. Критерии приёмки (по требованиям заказчика)

1. **Порядок по аудиту.** `mcp_attack quickstart --url … --audit stand.json` запускает варианты в
   порядке severity находок; `--audit-min-severity`/`top_n` работают; незамапленные rule_id дают
   явную `limitations`-заметку, а не молчаливую потерю. *(D1, D2)*
2. **Таксономия у всех.** `validate-catalog --strict-taxonomy` = 0 ошибок; тест доказывает отсутствие
   memory-варианта без AMG-категории; в отчёте есть ASR-оси по `owasp_amg_category` **и**
   `technique_category`. *(A1, A2, A4)*
3. **Indirect через тулы.** Есть нейтральные пулы email/web-search/document; движок исполняет
   `tool_result` и `document_ingestion`; неподдержанный вектор → `NOT_EVALUATED`, не ложный CLEAN. *(B1, B2, B4)*
4. **Любой агент, white/black-box.** `quickstart` подключает произвольный OpenAI-совместимый агент без
   правки кода; `mcp_client`/`http_generic`/`callable` документированы; `docs/attacker.md` содержит
   пример «новый агент за 40 строк». *(B3, D4)*
5. **Нейтральный пул.** `catalog/prompts/generic` не содержит доменной лексики (тест-стоп-лист);
   доменные промпты вынесены в `domain/invest_bank`. *(A3)*
6. **LLM-адаптация/мутация/генерация.** Есть `domain_adaptation`, `LLMSynthesisGenerator`,
   `run_adaptive`; сгенерированные варианты проходят `validate_variant_dict` и отдельно бьются в
   `asr_by_source`. *(C1, C2, C3)*
7. **Удобство.** Один happy-path CLI-вызов (`quickstart --url --model`); один воспроизводимый
   quickstart-нотбук, проходящий без стенда и без ключей. *(D2, D5)*

Все существующие тесты (`tests/test_attack_*.py`) остаются зелёными; новые фичи покрыты юнит-тестами,
перечисленными в разделах A–D как «Definition of done».
