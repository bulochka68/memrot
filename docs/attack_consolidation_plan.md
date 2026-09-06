# План консолидации `mcp_attack/` и `redteam/`

В репозитории две параллельные ветки атак на стенд. Они реализуют одну и ту же
идею (канареечная проверка гипотез аудита в словаре `rule_id`) разными руками.
Дублируется **ядро**, а не задачи — поэтому цель плана: убрать дублирование
ядра, оставив два пакета в разных ролях, а не слить их в один.

## Что есть сейчас

| | `mcp_attack/` (~2475 строк, 11 JSON-наборов) | `redteam/` (~948 строк) |
|---|---|---|
| Роль | переносимый **фреймворк**: каталог + движок | прикладной **конвейер** против живого стенда |
| Цель атаки | абстрактный `TargetAdapter` (adapters/base.py) | реальный HTTP `:8600` (attacks/targets/stand.py) |
| Запуск | `python -m mcp_attack run` | `pytest` + `rank_targets.py` / `select_attacks.py` |
| Зависимости | самодостаточен, оффлайн-тестируем | требует поднятого стенда и двух API-ключей |

## Дублирующиеся концепты

| Концепт | `mcp_attack/` | `redteam/` | Что делать |
|---|---|---|---|
| Абстракция цели | `adapters/base.py::TargetAdapter` (`new_session`/`send`/`consolidate`/`inspect_memory`/`ground_truth_check`) | `attacks/target.py::AttackTarget` (`new_session`/`deliver`/`trigger_persist`/`observe`) | один интерфейс (см. шаг 1) |
| Канарейка-оракул | `detectors/ground_truth.py` + движок | `target.py::canary()` | взять из `mcp_attack` |
| Таксономия | `taxonomy.py` (OWASP AMG + MITRE ATLAS) | `attack_taxonomy.py` (9 своих категорий) | один словарь (шаг 2) |
| Связь с аудитом | `audit_bridge.py` — только фильтр по `rule_id` | `rank_targets.py` + `select_attacks.py` — ранжирование по severity/трифекте | перенести ранжирование в bridge (шаг 3) |
| Сценарии отравления | каталог `mem02_*`, `mem01_03_*` | `scenarios/poisoning.py` (боевые RU-инъекции) | вынести в каталог (шаг 4) |
| Вердикт / path_state | `runner/verdict.py`, тип `Verdict` | инлайн в `target.py`/сценариях | взять из `mcp_attack` |

## Целевая архитектура

```
mcp_attack/     — библиотека: движок, каталог+схема, мутации, детекторы,
                  таксономия, мост к аудиту (фильтр + ранжирование)
     ▲
     │ импорт (redteam становится потребителем, а не двойником)
     │
redteam/        — тонкий раннер под конкретный стенд:
                  StandTarget реализует mcp_attack.TargetAdapter,
                  pytest-обвязка, внешние инструменты (PyRIT, garak,
                  promptfoo, mcp-scan)
```

Полное слияние в один пакет **не делаем**: у пакетов разные жизненные циклы
(оффлайн-тестируемая библиотека против тестов, требующих `docker compose up`
и ключей), и `redteam/` ценен именно как читаемый «ручной» слой.

## Шаги

### Шаг 1. Один интерфейс цели

`redteam/attacks/targets/stand.py::StandTarget` реализует
`mcp_attack.adapters.base.TargetAdapter` вместо самописного `AttackTarget`.
Маппинг методов (почти совпадают):

```
AttackTarget.deliver         → TargetAdapter.send
AttackTarget.trigger_persist → TargetAdapter.consolidate
AttackTarget.observe         → (probe через send) + ground_truth_check
AttackTarget.new_session     → new_session (без изменений)
AttackTarget.principals      → capabilities() / принципалы движка
```

Итог: каталог `mcp_attack` можно гонять прямо против живого стенда, а не только
против абстрактного адаптера. `redteam/attacks/target.py` (Protocol, canary,
AttackResult) удаляется — его роль берёт `mcp_attack.models` + `TargetAdapter`.

Проверка: `redteam` pytest-сценарии проходят через `StandTarget` как адаптер.

### Шаг 2. Один словарь таксономии

`redteam/attack_taxonomy.py` (9 категорий: `memory-poisoning`, `tool-poisoning`,
`idor-bac`, `token-validation`, `delegation`, `exfiltration`, `memory-hygiene`,
`infrastructure`, `inventory`) → тонкий маппинг поверх
`mcp_attack/taxonomy.py`, а не второй независимый список. Иначе два словаря
категорий разъезжаются при любом изменении.

Решить: категории `redteam` (по доменам правил аудита) и категории OWASP AMG
в `mcp_attack` — это две проекции. Оставить обе, но одну как производную от
другой через явную таблицу соответствия.

### Шаг 3. Один мост к аудиту

`audit_bridge.py` сейчас умеет только фильтровать/приоритизировать каталог по
`rule_id` находок. `rank_targets.py`/`select_attacks.py` умеют больше —
ранжируют по severity и участию в трифекте, дают локатор кода и preconditions.
Это то, чего мосту не хватает.

Перенести логику ранжирования в `mcp_attack/audit_bridge.py` (новая функция
рядом с `filter_variants_by_audit`), а `redteam/rank_targets.py` и
`select_attacks.py` сделать тонкими CLI-обёртками над ней. Один источник правды
о том, как отчёт аудита превращается в приоритеты атак.

Сохранить поведение: пустой аудит / нет пересечений → полный каталог с
`limitations` (уже реализовано в bridge, не потерять при переносе).

### Шаг 4. Один каталог payload'ов

Боевые русские инъекции из `redteam/attacks/scenarios/poisoning.py`
(`UNIVERSAL_RULE`, `FACT_STYLE_RULE`, `TOOL_FACT_STYLE_RULE`, …) вынести в
JSON-каталог `mcp_attack/catalog/prompts/` как варианты с `rule_ids` и
`propagation`. Тогда они получают схему, 7 техник мутации и детекторы
`mcp_attack` бесплатно, а не остаются захардкоженными строками.

Двухуровневый оракул `redteam` (`marker_in_policy` + `cross_user`) уже
покрывается `ground_truth`-детектором и canary-движком — переложить на них.

### Шаг 5. Тесты и CI

- `tests/test_attack_*.py` — ядро `mcp_attack`, оффлайн, остаются как есть.
- `redteam`-тесты требуют поднятого стенда — вынести в отдельный CI-job
  (не в общий прогон), помечать маркером pytest, пропускать без `STAND_URL`.
- После шага 1 добавить smoke-тест: каталог `mcp_attack` прогоняется против
  `StandTarget` (за флагом наличия стенда).

## Порядок и риски

Порядок: **2 → 3 → 1 → 4** (таксономия и мост дешевле и безопаснее; интерфейс
цели и каталог — крупнее и рискованнее, их последними).

Главный риск — сломать работающие против реального стенда pytest-сценарии
`redteam/` ради косметики. Поэтому каждый шаг проверяется прогоном:

```bash
python -m pytest tests/test_attack_*.py -q
python -m mcp_attack list-catalog --catalog mcp_attack/catalog/prompts
python -m mcp_attack validate-catalog mcp_attack/catalog/prompts
# redteam против стенда — отдельным job'ом, с поднятым docker compose
```

## Что НЕ делать

- Не сливать в один пакет с общим жизненным циклом — оффлайн-библиотека и
  требующий стенда раннер конфликтуют в CI.
- Не удалять внешнюю интеграцию `redteam/` (PyRIT, garak, promptfoo, mcp-scan):
  это её уникальная ценность, в `mcp_attack` её нет.
- Не менять словарь `rule_id` — это единственное звено между аудитом и атаками;
  его согласованность важнее внутренней структуры любого из пакетов.

## Смежные документы

* [`redteam/PIPELINE.md`](../redteam/PIPELINE.md) — текущий конвейер аудит → атаки
* [`redteam/attacks/README.md`](../redteam/attacks/README.md) — харнесс и внешние инструменты
* [`docs/porting_to_a_new_stand.md`](porting_to_a_new_stand.md) — перенос аудита на другой стенд
