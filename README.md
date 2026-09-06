# Аудитор агентных систем (`mcp_audit`) + red-team харнесс

Инструментарий оценки безопасности агентных (GenAI) систем: **offline-аудитор**,
который собирает факты из конфигураций, исходников, политик, деплоя и трасс и
выдаёт отчёт по схеме `agent-security-audit` 2.0, и **red-team харнесс**, который
переводит статические гипотезы аудита в runtime-подтверждения.

Сам тестовый стенд (GenAI Investment Assistant — LibreChat, Keycloak, `mcp-invest`,
`invest-server`, compose-файл) в этой ветке **не лежит**: здесь остаётся только
инструментарий. Аудитор к стенду не привязан — он работает с любой системой через
профиль и адаптеры, а харнесс — через адаптер цели (`redteam/attacks/targets/`).
Материалы по стенду сохранены как эталонные данные: профиль
`profiles/genai_invest_stand.json`, снимки и отчёты в `examples/`, фикстуры в
`tests/fixtures/stand/`.

## Содержание

- [Устройство репозитория](#устройство-репозитория)
- [Быстрый старт](#быстрый-старт)
- [Прогон аудита](#прогон-аудита)
- [Режимы и профили доступа](#режимы-и-профили-доступа)
- [Red-team харнесс](#red-team-харнесс)
- [Тесты](#тесты)
- [Аудит другой системы](#аудит-другой-системы)
- [Документация](#документация)

## Устройство репозитория

```text
mcp_audit/               — движок аудита 2.0
  discovery/             — разбор MCP-конфигов, контекстных файлов, live-хендшейк
  adapters/              — источники фактов: inventory, source, policy, deployment, trace, memory
  static_analysis/       — линтер описаний, коллизии, схемы, хеши, сверка с исходниками
  control_rules/         — каталог правил (MEM / AUTH / INFRA / TOOL / EGRESS / INV)
  correlation/           — trifecta и сведение вердикта
  active/                — controlled-validation: пробы на изолированной фикстуре
  reporting/             — JSON/Markdown-отчёт, obsec-экспорт, baseline и drift
  cli.py                 — точка входа `python -m mcp_audit`
profiles/                — профили систем: genai_invest_stand.json, rest_native_agent.json
schemas/                 — JSON-схема отчёта agent-security-audit 2.0
examples/                — манифесты, снимки и эталонные отчёты
docs/                    — архитектура, руководство аудитора, каталог правил, форматы
tests/                   — тесты подсистемы аудита (offline, ничего не поднимают)
redteam/                 — харнесс атак: ранжирование целей, отбор категорий, сценарии
  attacks/targets/       — адаптеры конкретных систем под атакой
  PIPELINE.md            — сквозной конвейер «аудит → атаки → регрессия защиты»
```

## Быстрый старт

Нужен Python 3.11+. Offline-аудит и все тесты работают **на стандартной библиотеке**,
без установки зависимостей:

```bash
python3 -m mcp_audit rules            # каталог правил
python3 -m mcp_audit --help
```

Зависимости из `requirements.txt` нужны только для отдельных режимов: `PyYAML` —
чтобы читать YAML-манифесты и `docker-compose.yml` (JSON-снимок деплоя читается без
неё), `httpx` + `pytest` — для харнесса атак и тестов.

```bash
pip install -r requirements.txt
```

## Прогон аудита

```bash
mkdir -p .audit

# 1) по заранее снятым снимкам — воспроизводит эталонный пример из examples/
python3 -m mcp_audit audit examples/genai_invest_stand.manifest.json \
  --json .audit/snapshot.json --md .audit/snapshot.md --gate

# 2) обычный MCP-конфиг клиента автоматически заворачивается в манифест (offline)
python3 -m mcp_audit audit examples/mcp_config.example.json \
  --json .audit/config.json --md .audit/config.md

# 3) валидация готового отчёта по схеме и миграция отчётов 1.x → 2.0
python3 -m mcp_audit validate .audit/snapshot.json
python3 -m mcp_audit migrate old_v1.json -o new_v2.json
```

Коды возврата `--gate`: `0` — оценка полная и нарушений в скоупе нет, `1` —
подтверждённые находки, `2` — неполная/неопределённая оценка (неизвестный
обязательный контроль никогда не считается разрешением), `3` — drift, `4` — ошибка
аудита. Неполнота и нарушение различаются машинно.

Манифест `examples/genai_invest_stand.local.manifest.json` читает исходники стенда
из рабочего дерева (`source_snapshot` с `root: ".."` и настоящий
`docker-compose.yml`) — он рассчитан на чекаут, где рядом с аудитором лежит сам
стенд. В этой ветке стенда нет, поэтому такой прогон честно вырождается в
`partial / undetermined`; правьте пути под свой чекаут стенда или пользуйтесь
снимочным манифестом выше.

## Режимы и профили доступа

| Режим | Что делает | О чём позволяет судить |
|---|---|---|
| `offline` (по умолчанию) | разбирает конфиги, исходники, политики и снимки; ничего не запускает и никуда не подключается | статические факты, допущения, расхождения |
| `live-inventory` | выполняет MCP-хендшейк | каталог, объявленный **этой** личности в **этот** момент |
| `trace-review` | читает события выполнения и памяти | только то, что показывают события, с их покрытием |
| `controlled-validation` | гоняет **зарегистрированные** контрольные кейсы на изолированной фикстуре | конкретный инвариант внутри фикстуры |
| `baseline-comparison` | сравнивает совместимые снимки | классифицированные изменения и их согласование |

`--access-profile black_box | grey_box | white_box` — независимая ось: какие
источники доступны. Подробности, Python API и live-режимы — в
[`docs/auditor.md`](docs/auditor.md).

Каждое утверждение отчёта — claim со своим `source_type`, `method`,
`claim_status` (hypothesis / static_supported / runtime_supported / contradicted /
inconclusive), `evidence_refs`, `scope`, качественной уверенностью и ограничениями.
Никакого общего флага «проверено» и никакого единого «процента безопасности».

## Red-team харнесс

`redteam/` замыкает петлю: аудит даёт гипотезы (static), атаки подтверждают их
(runtime) в том же словаре правил. Ядро (`target.py`, сценарии, таксономия) не знает
о конкретной системе — специфика живёт в адаптере `redteam/attacks/targets/`.

```bash
# цели по убыванию severity из отчёта аудита
python3 redteam/rank_targets.py .audit/snapshot.json --min-severity HIGH

# отбор категорий атак под найденные цели
python3 redteam/select_attacks.py .audit/snapshot.json --from-audit \
  -c tool-poisoning,memory-poisoning --include-unresolved

# план атак: сухой прогон, по системе не бьёт, живая цель не нужна
python3 redteam/attacks/run_attacks.py .audit/snapshot.json \
  -c tool-poisoning,memory-poisoning --dry-run
```

Живой прогон требует поднятой цели и двух разных принципалов
(`STAND_URL`, `ATTACKER_KEY`, `VICTIM_KEY`) — только против своего стенда: эти
режимы реально ходят по сети. Полный конвейер, включая регрессию защиты, —
[`redteam/PIPELINE.md`](redteam/PIPELINE.md).

## Тесты

```bash
python3 -m pytest -q
```

Тесты подсистемы аудита offline: работают по снимкам и фикстурам из `examples/` и
`tests/fixtures/`, ничего не поднимают и никуда не ходят.

## Аудит другой системы

- **Аудит**: новый профиль `profiles/<system>.json` (компоненты, хранилища памяти,
  потоки для проверки в исходниках, переходы авторизации, валидация токенов) плюс
  привязки адаптеров в манифесте. Правила и движок не меняются.
- **Атаки**: новый адаптер `redteam/attacks/targets/<system>.py` с реализацией
  `AttackTarget`. Сценарии, таксономия и раннер не меняются.

Форматы входов и адаптеров — [`docs/adapters_and_formats.md`](docs/adapters_and_formats.md).

## Документация

- [`docs/auditor.md`](docs/auditor.md) — руководство по подсистеме аудита 2.0
- [`docs/audit_subsystem_architecture.md`](docs/audit_subsystem_architecture.md) — архитектура
- [`docs/rules_catalog.md`](docs/rules_catalog.md) — каталог правил (генерируется `python -m mcp_audit rules --markdown`)
- [`docs/adapters_and_formats.md`](docs/adapters_and_formats.md) — адаптеры и форматы входов
- [`docs/migration_v1_to_v2.md`](docs/migration_v1_to_v2.md) — миграция отчётов 1.x → 2.0
- [`redteam/PIPELINE.md`](redteam/PIPELINE.md) — конвейер «аудит → атаки»
