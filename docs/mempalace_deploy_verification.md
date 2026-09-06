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

```bash
mempalace init ./demo --yes --auto-mine   # скачивает эмбеддер all-MiniLM-L6-v2 (~80 МБ)
mempalace status
mempalace search "why did we switch to GraphQL"
```

Результат: замайнились файлы, `search` вернул корректный топ-хит
(`cosine_sim=0.601`).

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
