# Пайплайн тестирования: от offline-аудита до запуска атак

Единый конвейер поверх подсистемы аудита (`mcp_audit`) и red-team харнесса
(`redteam/`). Все команды — из корня репозитория. Петля: аудит находит гипотезы
(static), атаки подтверждают их (runtime) в том же словаре правил.

```
mcp_audit audit ──> stand.json ──> rank_targets ──> select_attacks
                                                          │
                                                    run_attacks
                                                          │
     static_path_supported ──> runtime_path_observed ──> control_violation_observed
```

## 0. Подготовка (один раз)

```bash
cd /home/user/aith_redteaming
pip install -r requirements.txt          # движок аудита
pip install pytest httpx                 # харнесс атак
mkdir -p .audit                          # отчёты (в .gitignore)
```

## 1. Offline-аудит (статика, ничего не поднимается)

```bash
python3 -m mcp_audit audit examples/genai_invest_stand.local.manifest.json \
  --json .audit/stand.json --md .audit/stand.md --gate
```
Читает исходники + compose + политику → `.audit/stand.json`. Exit 1 = есть
находки (норма). Дальше в работу идёт только `control_outcome=FAIL`.

## 2. Ранжирование целей

```bash
python3 redteam/rank_targets.py .audit/stand.json --min-severity HIGH
```
Цели по убыванию severity и участия в trifecta: что бить, где (файл:строка),
какой инвариант ломать, при каких условиях.

## 3. Отбор категорий

```bash
python3 redteam/select_attacks.py --list-categories
python3 redteam/select_attacks.py .audit/stand.json --from-audit \
  -c tool-poisoning,memory-poisoning --include-unresolved
```
`NOT_EVALUATED`/`INCONCLUSIVE` уходят в блок «сначала перевести в проверяемый режим».

## 4. План атак (сухой прогон, по системе не бьёт)

```bash
cd redteam/attacks
python3 run_attacks.py ../../.audit/stand.json -c tool-poisoning,memory-poisoning --dry-run
```
Показывает сценарий по каждой цели. Живой стенд не нужен.

## 5. Поднять стенд и завести принципалов

```bash
cd /home/user/aith_redteaming
docker compose up -d                     # agent-api на :8600
export STAND_URL=http://localhost:8600
export ATTACKER_KEY=<ключ пользователя A> # со страницы аккаунта стенда
export VICTIM_KEY=<ключ пользователя B>   # ДРУГОЙ пользователь
```

## 6. Прогон атак (runtime-подтверждение)

```bash
cd redteam/attacks

# А) раннер по целям из отчёта — результат в словаре аудита
python3 run_attacks.py ../../.audit/stand.json -c memory-poisoning,tool-poisoning --json

# Б) детальные pytest-сценарии
python3 -m pytest test_memory_poisoning.py -v
SINKHOLE_QUERY=<управляемый источник> python3 -m pytest test_tool_poisoning.py -v

# В) быстрые одиночные пробы
npx promptfoo@latest eval -c promptfoo.poisoning.yaml
```

`run_attacks.py --json` возвращает `path_state` каждой цели:
```
static_path_supported      → вживую не воспроизвелось
runtime_path_observed      → инъекция опубликована в общую политику
control_violation_observed → маркер дошёл до жертвы (межпользовательский payoff)
```

## 7. Регрессия защиты

Те же атаки против защищённого пути (`auth_mode=protected`) должны стать
зелёными — это доказывает, что защита закрывает именно найденный дефект.

## Одной строкой (стадии 1→4, без удара по системе)

```bash
mkdir -p .audit && \
python3 -m mcp_audit audit examples/genai_invest_stand.local.manifest.json --json .audit/stand.json --gate; \
python3 redteam/attacks/run_attacks.py .audit/stand.json -c tool-poisoning,memory-poisoning --dry-run
```

## Обобщение на другую систему

- Аудит: новый профиль (`profiles/<system>.json`) + привязки адаптеров в манифесте.
- Атаки: новый адаптер `redteam/attacks/targets/<system>.py` (реализовать
  `AttackTarget`). Сценарии, таксономия и раннер не меняются.

Только против своего стенда: live-режимы аудита и все атаки реально ходят по сети.
