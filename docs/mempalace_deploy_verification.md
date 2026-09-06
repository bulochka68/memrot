# Развёртывание и проверка стенда MemPalace (ветка `main`)

Отчёт о том, как поднять стенд [MemPalace](https://github.com/MemPalace/mempalace)
из ветки `main` и убедиться, что он работает. Все шаги ниже реально выполнены и
проверены в этой среде.

- **Репозиторий:** https://github.com/MemPalace/mempalace
- **Ветка / коммит:** `main` @ `d5250c7`
- **Версия:** MemPalace 3.9.0
- **Дата проверки:** 2026-09-06

## Что это за «стенд»

MemPalace на `main` — это Python-пакет: CLI + MCP-сервер локальной памяти поверх
ChromaDB. В контексте нашего репозитория `aith_redteaming` «развернуть стенд»
означает поднять его так, как использует attack-сторона, то есть **общий MCP-хаб
по HTTP** (`deploy/docker-compose.server.yml` → `http://HOST:8765/mcp`,
bearer-токен), в который бьёт `examples/mempalace.attack.config.json`.

> `main` — релизная ветка MemPalace (тегированные стабильные релизы). Дефолтная
> ветка проекта — `develop`; повседневная разработка идёт туда, а `main`
> продвигается мержем `develop` под тег.

## Шаги развёртывания (проверены)

### 1. Получить `main`

```bash
git clone https://github.com/MemPalace/mempalace && cd mempalace
git checkout main
```

### 2. Установка

Docker-путь в этой среде недоступен (см. «Ограничения окружения»), поэтому
ставим нативно через `uv` (подойдёт и `pip`):

```bash
uv venv --python 3.12 .venv && . .venv/bin/activate
uv pip install -e ".[dev]"     # или: pip install -e ".[dev]"
mempalace --version            # → MemPalace 3.9.0
```

### 3. Дымовой тест CLI (палаца + майнинг + поиск)

`mempalace init <dir>` настраивает индексацию **уже существующего** каталога с
контентом (сканирует его структуру для комнат) — сам каталог он не создаёт.
Поэтому сначала создаём папку с файлами (или указываем на реальный проект),
и только потом `init`, иначе будет `ERROR: Directory not found`.

```bash
mkdir -p ./demo                                  # init не создаёт каталог сам
printf '# Notes\nWe chose GraphQL over REST for field selection.\n' > ./demo/notes.md
mempalace init ./demo --yes --auto-mine --no-llm # --no-llm гасит warning про Ollama;
                                                 # скачивает эмбеддер all-MiniLM-L6-v2 (~80 МБ)
mempalace status
mempalace search "GraphQL"
```

Результат: замайнились файлы, `search` вернул корректный топ-хит
(`cosine_sim=0.601`).

> `No LLM provider reachable … Running heuristics-only` — это предупреждение, а
> не ошибка (нет запущенной Ollama); индексации не мешает, `--no-llm` его гасит.

### 4. Поднять HTTP-хаб (то, что атакует attack-config)

```bash
export MEMPALACE_MCP_HTTP_TOKEN=$(openssl rand -hex 32)
mempalace serve --host 0.0.0.0 --port 8765
```

## Проверка «что всё работает»

Против живого хаба прогнан весь контракт, на который завязан
`examples/mempalace.attack.config.json`:

| Проверка | Результат |
| --- | --- |
| `GET /healthz` (без авторизации) | **200 `ok`** |
| `POST /mcp` без токена | **401** (авторизация обязательна) |
| `initialize` с bearer-токеном | **200**, `serverInfo: mempalace 3.9.0` |
| `tools/list` | **45 MCP-инструментов** |
| `tools/call mempalace_search` | ✅ вернул дровер |
| `mempalace_add_drawer` → `mempalace_search` (запись → чтение) | ✅ round-trip прошёл |

### Тесты (паритет с CI)

```bash
python -m pytest tests/ --ignore=tests/benchmarks \
  --cov=mempalace --cov-fail-under=80 --durations=10
```

Результат: **4708 passed, 4 failed, 59 skipped, покрытие 82.62%** (порог 80
пройден).

Четыре «падения» — артефакт запуска **от root** в контейнере: тесты
рассчитывают, что `chmod 0o000` и read-only каталоги запрещают доступ, а root
их всё равно читает/пишет:

- `tests/test_mcp_server.py::TestStaleLibraryGate` — 3 теста
- `tests/test_sqlite_exact_backend.py::test_sqlite_exact_read_only_open_sees_active_writer_wal`

Перезапуск тех же классов от непривилегированного пользователя (`nobody`) даёт
**73/73 passed**. На не-root раннерах CI (ubuntu / macos / windows) они зелёные.
Это не дефект MemPalace, а следствие запуска под uid 0.

## Запуск аудитора (`mcp_audit`)

`mcp_audit` — подсистема аудита безопасности из этого репозитория (движок 2.0,
схема отчёта `agent-security-audit` 2.0, 28 правил: MEM-*, AUTH-*, INFRA-*,
TOOL-*, EGRESS-*, INV-*). Для MemPalace перенос сделан **только данными**: аудит
не читает чужой чек-аут и ничего не запускает — он работает офлайн по
зафиксированным снимкам (`examples/mempalace.*.json`), профиль —
`profiles/mempalace.json`. Все команды выполняются из корня `aith_redteaming`.

### 1. Проверить профиль до аудита (`lint-profile`)

```bash
python -m mcp_audit lint-profile profiles/mempalace.json \
  --root /path/to/mempalace/checkout \
  --sources mcp_inventory,source_snapshot,policy_snapshot,deployment
```

Проверяет структуру профиля, что все `path` / `symbol` резолвятся в дереве
исходников, что регулярки компилируются и `rule_refs` ссылаются на реальные
правила, и печатает карту покрытия. Ожидаемо: `clean`, `planned rules 25/28`
(вне охвата: TOOL-01 — нужен baseline; EGRESS-02 / INFRA-03 — нужны
control_fixtures). `--root` нужен только для проверки локаторов; без него эти
проверки пропускаются, и сам офлайн-аудит (шаги 2–3) чек-аут MemPalace не
требует вовсе.

### 2. Прогнать аудит

```bash
mkdir -p .audit
python -m mcp_audit audit examples/mempalace.manifest.json \
  --json .audit/mempalace.json --md .audit/mempalace.md
```

Манифест `examples/mempalace.manifest.json` сшивает четыре снимка-адаптера
(`mcp_inventory`, `source_snapshot`, `policy_snapshot`, `deployment`). Прогон
воспроизводит эталонный отчёт `examples/mempalace.audit.json`: **14 находок
(11 confirmed + 3 hypotheses)**, вывод `findings_present`, состояние `partial`
(часть контролов не покрыта снимками — неизвестный обязательный контрол это
никогда не «allow»).

### 3. Гейт для CI и валидация отчёта

```bash
# гейт: exit 1 при подтверждённых находках, 2 при неполной оценке, 0 — чисто
python -m mcp_audit audit examples/mempalace.manifest.json \
  --json .audit/mempalace.json --gate

# структурная валидация отчёта v2 (референтная целостность)
python -m mcp_audit validate .audit/mempalace.json
```

Коды возврата `audit`: `0` — без нарушений в охвате, `1` — подтверждённые
находки, `2` — оценка неполная, `3` — drift, `4` — ошибка аудита. На стенде
MemPalace `--gate` даёт **exit 1** (есть находки), `validate` — **0 ошибок**.

Полное описание режимов (`offline` / `live-inventory` / `trace-review` /
`controlled-validation` / `baseline-comparison`), профилей и правил —
в [`docs/auditor.md`](auditor.md) и
[`docs/porting_to_a_new_stand.md`](porting_to_a_new_stand.md).

## Ограничения окружения

**Docker-путь здесь не работает** из-за egress-политики прокси — blob-CDN
отдают `403 Forbidden`:

- `docker pull ghcr.io/mempalace/mempalace:latest` → 403 (`pkg-containers.githubusercontent.com`)
- `docker pull qdrant/qdrant:latest`, `docker pull python:3.12-slim` → 403 (`production.cloudfront.docker.com`)
- как следствие, `docker build` падает уже на базовом образе `python:3.12-slim`

Отсюда практические выводы для этой среды:

- разворачивать нативно через `uv` / `pip`, а не через Docker;
- для `serve` использовать бэкенд по умолчанию (ChromaDB), а не Qdrant-хаб из
  `deploy/docker-compose.server.yml` — образ Qdrant не тянется;
- эмбеддер брать `minilm` (качается с S3-зеркала Chroma — доступно), а не
  `embeddinggemma` (идёт с `huggingface.co`, который отсюда не резолвится).

## Дальше

Стенд поднимается и проходит проверку. Следующий логичный шаг — прогнать связку
**audit → attack** из этого репозитория против поднятого хаба:

```bash
export MCP_ATTACK_CRED_MEMPALACE_TEAM_TOKEN="$MEMPALACE_MCP_HTTP_TOKEN"
python -m mcp_attack run --config examples/mempalace.attack.config.json --out .attack
```
