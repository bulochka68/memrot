# Тестирование атак в WSL 2

Как прогонять red-team атаки этого репозитория (`mcp_attack` + `redteam/attacks`)
из **Windows Subsystem for Linux 2**. Разбирает то, что в WSL 2 отличается от
Linux/macOS: доставку запросов из контейнеров к Ollama, различие Docker Desktop
и нативного `dockerd`, самоподписанный TLS Keycloak и файловую систему.

Всё автоматизировано в `scripts/wsl2_attack_stand.sh` — этот документ объясняет,
что скрипт делает и как то же сделать руками.

---

## TL;DR

```bash
# из WSL 2, в корне репозитория (репозиторий — на ext4, НЕ в /mnt/c, см. §2)
./scripts/wsl2_attack_stand.sh check     # префлайт: docker, python, ollama, файлы
./scripts/wsl2_attack_stand.sh smoke     # ПУТЬ A: движок атак офлайн, без Docker

# ПУТЬ B (полный стенд) — нужен keycloak/realm-export.json (см. §0) и Docker:
./scripts/wsl2_attack_stand.sh setup     # сертификат Keycloak + .env + Ollama-обвязка
./scripts/wsl2_attack_stand.sh up        # поднять стенд, дождаться healthy
#   -> открыть http://localhost:8501, взять ДВА API-ключа (атакующий+жертва)
./scripts/wsl2_attack_stand.sh attack --url http://localhost:8600/v1 --model genai-invest-agent
```

---

## 0. Важное про этот клон (прочитать до §4)

Два файла, нужных для стенда, в репозитории **отсутствуют** (не закоммичены):

| Файл | Статус | Влияние | Решение |
|---|---|---|---|
| `.env.example` | **восстановлен** в этом PR | был сломан первый шаг README (`cp .env.example .env`) | готов к использованию |
| `keycloak/realm-export.json` | **отсутствует** | без него Keycloak стартует, но realm `genai-stand`, клиенты (`librechat`, `agent-service`, …) и пользователи `client1001…client1005` не импортируются → стенд не аутентифицирует запросы, **ПУТЬ B не поднимется** | получить у мейнтейнеров / из приватного источника и положить в `keycloak/realm-export.json` |

`ПУТЬ A` (офлайн-движок атак, §3) от Keycloak **не зависит** и работает сразу.
`ПУТЬ B` (полный стенд, §4) требует `keycloak/realm-export.json`.

`scripts/wsl2_attack_stand.sh up` заранее проверяет наличие realm-файла и
останавливается с понятной ошибкой, а не поднимает заведомо нерабочий стенд.

---

## 1. Два способа «протестировать атаки»

| | ПУТЬ A — офлайн-движок | ПУТЬ B — полный стенд |
|---|---|---|
| Что запускается | `mcp_attack` против любого OpenAI-совместимого эндпоинта + офлайн pytest | весь стенд в Docker + атаки против живого `agent-api` |
| Нужен Docker | нет | да |
| Нужен `keycloak/realm-export.json` | нет | **да** |
| Нужна Ollama/LLM | только для реального прогона (`quickstart`), не для валидации | да |
| Что доказывает | движок, каталог, таксономия, детекторы исправны; ASR против внешнего агента | реальные BAC/IDOR и межпользовательское отравление памяти на уязвимом стенде |
| Команда | `./scripts/wsl2_attack_stand.sh smoke` | `./scripts/wsl2_attack_stand.sh up && … attack` |

Начните с ПУТИ A — он подтверждает, что WSL 2 сам по себе всё тянет, и не зависит
от отсутствующего realm-файла.

---

## 2. Подготовка WSL 2

**Файловая система.** Клонируйте репозиторий в домашний каталог WSL (`~/…`, ext4),
а не в `/mnt/c/…`. На `/mnt/c` теряется бит `+x` у скриптов, ломаются переносы
строк (CRLF), и Docker-сборки/тесты работают в разы медленнее.

```bash
cd ~ && git clone <repo-url> aith_redteaming && cd aith_redteaming
```

Если файл всё же пришёл с CRLF: `sed -i 's/\r$//' scripts/wsl2_attack_stand.sh`.

**Docker — два варианта, скрипт различает их сам:**

- **Docker Desktop + WSL integration** (проще всего). В Docker Desktop:
  *Settings → Resources → WSL integration →* включить для вашего дистрибутива.
  `host.docker.internal` уже указывает из контейнеров на **Windows-хост**.
- **Нативный `dockerd` внутри дистрибутива** (`sudo apt install docker.io`,
  `sudo service docker start`). Здесь `host.docker.internal` по умолчанию **не
  определён** — скрипт добавит его через `docker-compose.override.yml` (§4.2).

Проверка: `./scripts/wsl2_attack_stand.sh check`.

**Python-зависимости** (для харнесса, запускаемого из WSL-хоста):

```bash
python3 -m pip install --user pytest httpx pydantic
# для белого ящика genai_invest (инспекция памяти) дополнительно:
python3 -m pip install --user pymongo redis
```

---

## 3. ПУТЬ A — офлайн, без Docker (работает сразу)

Одной командой:

```bash
./scripts/wsl2_attack_stand.sh smoke
```

Она выполняет (можно и вручную, из корня репо, с `PYTHONPATH=.`):

```bash
# 1) каталог атак валиден и таксономия строгая (AMG на каждом memory_poisoning и т.д.)
python3 -m mcp_attack validate-catalog mcp_attack/catalog/prompts --strict-taxonomy

# 2) инвентарь вариантов доменного оверлея банка
python3 -m mcp_attack list-catalog --catalog mcp_attack/catalog/prompts/domain/invest_bank

# 3) офлайн-тесты движка
python3 -m pytest -q tests/test_attack_catalog_loader.py tests/test_attack_taxonomy.py \
                     tests/test_attack_catalog_taxonomy_strict.py tests/test_attack_config.py
```

**Атака против произвольного OpenAI-совместимого агента** (без стенда — например,
против вашего собственного агента или Ollama-модели напрямую):

```bash
python3 -m mcp_attack quickstart \
  --url http://localhost:11434/v1 --model qwen3:8b \
  --adapter openai_compat --out .attack --report-html .attack/run.html
```

Отчёты: `.attack/run.md`, `.attack/run.html`, трасса `.attack/trace.jsonl`.

---

## 4. ПУТЬ B — полный стенд в Docker

### 4.1 Предпосылки

1. `keycloak/realm-export.json` на месте (см. §0) — иначе стенд не поднимется.
2. Самоподписанный TLS-сертификат Keycloak:
   `./scripts/wsl2_attack_stand.sh certs` (или команда `openssl` из README).
3. `.env`: `./scripts/wsl2_attack_stand.sh env` (создаст из `.env.example`).
4. LLM-провайдер: локальная Ollama (§4.2) **или** OpenRouter/иной (правится `.env`).

### 4.2 Ollama из контейнеров в WSL 2 (главная тонкость)

Контейнеру `agent-api` нужно достучаться до LLM. Ollama обязана слушать
`0.0.0.0`, а не `127.0.0.1`, и `OPENAI_BASE_URL` в `.env` должен вести на адрес,
видимый **из контейнера**. Матрица:

| Docker | Где Ollama | `OPENAI_BASE_URL` (в `.env`) | Что ещё сделать |
|---|---|---|---|
| Desktop | на **Windows** | `http://host.docker.internal:11434/v1` | на Windows: переменная среды `OLLAMA_HOST=0.0.0.0`, перезапустить Ollama, разрешить порт в брандмауэре |
| Desktop | в **WSL** | ⚠️ через `host.docker.internal` **не видна** (он указывает на Windows) | перенести Ollama на Windows, **либо** взять OpenRouter |
| нативный `dockerd` | в **WSL** | `http://host.docker.internal:11434/v1` | скрипт пишет `docker-compose.override.yml` с `host.docker.internal:host-gateway` для `agent-api`; запустить `OLLAMA_HOST=0.0.0.0 ollama serve` |
| нативный `dockerd` | на **Windows** | `http://<IP-Windows>:11434/v1` | `<IP-Windows>` = шлюз по умолчанию из WSL (`ip route`), Ollama на `0.0.0.0` |

`./scripts/wsl2_attack_stand.sh env` определяет flavor Docker, пробует Ollama на
`localhost` и на Windows-хосте, при нативном `dockerd` создаёт override и
печатает рекомендованный `OPENAI_BASE_URL`.

**Обход всей возни — OpenRouter** (реальный бюджет, без Ollama). В `.env`:

```env
OPENAI_API_KEY=<ключ OpenRouter>
OPENAI_BASE_URL=https://openrouter.ai/api/v1
RESEARCH_MODEL=openai:openai/gpt-5-mini
SUMMARIZATION_MODEL=openai:openai/gpt-5-mini
```

### 4.3 Подъём

```bash
./scripts/wsl2_attack_stand.sh up      # up -d --build + ожидание healthy + подсказки
# вручную эквивалентно:
docker compose up -d --build
docker compose ps                      # дождаться healthy у redis/mongo/postgres/keycloak/invest-server
```

Первый старт Keycloak с импортом realm — 20–40 с; зависящие сервисы ждут сами.
Браузер на Windows видит порты WSL по `localhost` (проброс WSL 2).

### 4.4 Получить два API-ключа

Атаки межпользовательские — нужны ключи **двух разных** пользователей:

1. Открыть `http://localhost:8501` → войти как `client1001` (пароль = логин).
2. Скопировать ключ `sk-genai-...` — это **атакующий**.
3. В приватном окне войти как `client1002`, скопировать ключ — это **жертва**.

### 4.5 Запуск атак

**Быстро (обёртка скрипта, quickstart):**

```bash
export CRED_ATTACKER=sk-genai-<ключ client1001>
export CRED_VICTIM=sk-genai-<ключ client1002>
./scripts/wsl2_attack_stand.sh attack \
  --url http://localhost:8600/v1 --model genai-invest-agent \
  -- --adapter genai_invest \
     --attacker-principal 1001 --victim-principal 1002 \
     --cred-attacker-env CRED_ATTACKER --cred-victim-env CRED_VICTIM
```

**Белый ящик по конфигу** (`examples/genai_invest_stand.attack.config.json` —
доменный оверлей invest_bank: BAC-инъекции, отравление памяти MEM-02/03, web-search):

```bash
# креды -> MCP_ATTACK_CRED_<credential_ref>; в конфиге refs = CUS_1001..CUS_1005
export MCP_ATTACK_CRED_CUS_1001=sk-genai-<ключ client1001>   # attacker
export MCP_ATTACK_CRED_CUS_1002=sk-genai-<ключ client1002>   # victim
python3 -m mcp_attack run --config examples/genai_invest_stand.attack.config.json \
  --out .attack --report-html .attack/run.html
```

> В примере конфига `target.binding.compose_dir` = `../genai-invest-agent-memory-stand`
> (путь из исходной раскладки). Для этого репозитория укажите корень репо (там, где
> `docker-compose.yml`), чтобы включить ground-truth-канал по логам `invest-server`;
> без него прогон всё равно идёт, помечая канал как недоступный. `base_url` в конфиге
> уже `http://localhost:8600/v1` — верно для запуска харнесса с WSL-хоста.

**Stateful pytest-сценарии** (`redteam/attacks` — цепочка poison→finalize→victim):

```bash
export STAND_URL=http://localhost:8600
export ATTACKER_KEY=sk-genai-<ключ client1001>
export VICTIM_KEY=sk-genai-<ключ client1002>
cd redteam/attacks
python3 -m pytest test_memory_poisoning.py -v     # MEM-02/03/04/06
python3 -m pytest test_tool_poisoning.py -v        # TOOL-04 (+ SINKHOLE_QUERY для полного пути)
```

**Оракул.** Инъекция велит агенту дописывать уникальный маркер-канарейку в каждый
ответ; маркер, всплывший в ответе **жертвы** (другого пользователя) = отравление
подтверждено. Извлечение фактов делает LLM → результат недетерминирован: тест, не
сработавший с первого раза, повторите или усильте формулировку (свойство цели, не бага).

### 4.6 vulnerable vs protected (регрессия защиты)

Стенд по умолчанию в режиме `auth_mode=vulnerable`. Те же атаки против
`protected` должны становиться зелёными (BAC проверяется на уровне IAM, а не по
параметру от модели). Переключение — полем `auth_mode` в запросе к `agent-api`
(см. основной README, раздел «Режимы vulnerable / protected»).

---

## 5. Скрипт `scripts/wsl2_attack_stand.sh`

| Команда | Что делает | Нужен Docker |
|---|---|---|
| `check` | префлайт: WSL, docker+daemon, compose, python, openssl, наличие `.env`/сертификата/realm, достижимость Ollama | нет |
| `smoke` | ПУТЬ A: `validate-catalog` + `list-catalog` + офлайн pytest | нет |
| `certs` | сгенерировать `keycloak/certs/{tls.crt,tls.key}` | нет |
| `env` | создать `.env` из примера; при нативном `dockerd` — `docker-compose.override.yml`; диагностика Ollama | нет |
| `setup` | `check` → `certs` → `env` | нет |
| `up` | проверить realm, поднять стенд, дождаться healthy, показать точки входа | да |
| `ps` / `down` | статус / остановка | да |
| `attack [--url U] [--model M] [-- …]` | обёртка `mcp_attack quickstart`, аргументы после `--` идут в CLI как есть | да (стенд поднят) |

Идемпотентность: `.env` создаётся только если его нет; override — аддитивный и в
`.gitignore`; сертификат не перегенерируется, если уже есть.

---

## 6. Troubleshooting (специфика WSL 2)

- **`docker daemon недоступен`.** Docker Desktop: запустите Desktop и включите WSL
  integration для дистрибутива. Нативный: `sudo service docker start`.
- **`agent-api` не видит Ollama / таймауты LLM.** Ollama слушает `127.0.0.1` —
  переключите на `0.0.0.0` (`OLLAMA_HOST=0.0.0.0`), проверьте `OPENAI_BASE_URL`
  по матрице §4.2. Диагностика: `./scripts/wsl2_attack_stand.sh env`.
- **Нативный `dockerd`: `host.docker.internal` не резолвится в контейнере.** Нужен
  `docker-compose.override.yml` с `host.docker.internal:host-gateway` (создаёт
  команда `env`); он уже в `.gitignore`.
- **Браузер ругается на сертификат `https://localhost:8443`.** Ожидаемо —
  самоподписанный TLS Keycloak (нужен LibreChat). Один раз «Advanced → Proceed».
- **`invalid_grant: Invalid token issuer`.** `KC_HOSTNAME` контейнера `keycloak`
  разошёлся с `KEYCLOAK_ISSUER_URL` в `.env` — оба обязаны быть `https://localhost:8443`.
- **`Permission denied` / скрипт «не исполняемый» на `/mnt/c`.** Перенесите репо в
  `~` (ext4). Быстрый обход: `bash scripts/wsl2_attack_stand.sh …`.
- **Токены «протухают» после сна Windows (рассинхрон часов WSL).** `wsl --shutdown`
  из PowerShell и заново, либо `sudo hwclock -s`.
- **Keycloak не подхватил правки realm.** `--import-realm` применяется только при
  пересоздании: `docker compose up -d --force-recreate keycloak`.
