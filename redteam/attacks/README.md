# Red-team harness: проверка находок аудита вживую

Переводит статические находки (`control_outcome=FAIL`) в наблюдаемый результат
против **своего локального стенда**. Каждый сценарий привязан к `rule_id` и его
`expected_invariant`; успех = находка становится `runtime_path_observed`.

## Фреймворки — что и зачем

| Инструмент | Роль здесь | Почему |
|---|---|---|
| **pytest + httpx** (этот харнесс) | основной | цепочка poison→finalize→victim межпользовательская и stateful — её не выражают одноходовые сканеры |
| **promptfoo** | быстрые одиночные инъекции + ассерты | стенд OpenAI-совместим и сам документирует promptfoo; см. `promptfoo.poisoning.yaml` |
| **Microsoft PyRIT** | генерация/мутация payload'ов | многоходовые джейлбрейки, converters; отдаёт строки в наш `StandClient.chat` |
| **NVIDIA garak** | широкий скан известных проб | быстрый первичный проход по одному эндпоинту |
| **Invariant mcp-scan** | tool-poisoning на уровне описаний | уже интегрирован в аудитор (`--mcp-scan`), бьёт по TOOL-05 |

Схема: аудит даёт цели (`rank_targets.py`/`select_attacks.py`) → payload'ы генерит
PyRIT/garak → доставку и оракул держит этот харнесс → результат возвращается в
словарь аудита (`runtime_path_observed`).

## Предпосылки

1. Цель поднята локально и доступна по `STAND_URL` (у genai-invest-стенда это
   `agent-api` на `:8600`; сам стенд живёт в отдельном репозитории/ветке).
2. Два API-ключа разных пользователей (страница аккаунта стенда):
   - `ATTACKER_KEY` — атакующий (user A)
   - `VICTIM_KEY` — жертва (user B)
3. `pip install -r requirements.txt` (httpx + pytest)

## Запуск

```bash
export STAND_URL=http://localhost:8600
export ATTACKER_KEY=<ключ A>
export VICTIM_KEY=<ключ B>

cd redteam/attacks
python3 -m pytest test_memory_poisoning.py -v      # MEM-02/03/04/06
python3 -m pytest test_tool_poisoning.py -v        # TOOL-04 (+ SINKHOLE_QUERY для полного пути)
```

## Оракул

Инъекция велит агенту дописывать уникальный **маркер-канарейку** в каждый ответ.
- `finalize` возвращает факты со `scope`; `global_facts()` показывает, что инъекция
  ушла в общую политику (MEM-02/03/06).
- Маркер в ответе **жертвы** (другого пользователя) = межпользовательское отравление
  подтверждено (payoff MEM-02, `build_context` без фильтра по user_id).

## Важно

- Извлечение фактов делает LLM — результат недетерминирован. Тест, не
  воспроизведшийся с первого раза, повторите или усильте «универсальность»
  формулировки; это свойство цели, а не бага харнесса.
- TOOL-04 полностью детерминирован только с управляемым веб-источником
  (`SINKHOLE_QUERY` → локальный sinkhole в выдаче поиска). Без него — только
  структурный дымовой тест.
- Только против своего стенда. `auth_mode=vulnerable` включает уязвимый путь;
  `protected` должен давать те же тесты зелёными (регрессия защиты).

## Обобщённый слой (generic)

Тот же шов, что у аудитора: сценарии generic, привязка к системе — в адаптере.

```
target.py              — AttackTarget (протокол), Principal, AttackResult, canary()
targets/stand.py       — StandTarget: единственное место с путями стенда
scenarios/poisoning.py — memory/tool poisoning, работают с любым AttackTarget
run_attacks.py         — отчёт аудита → цели → сценарии → path_state
```

Конвейер целиком:

```bash
# план без удара по системе
python3 run_attacks.py ../../.audit/stand.json -c tool-poisoning,memory-poisoning --dry-run

# реальный прогон против своего стенда, результат в словаре аудита
STAND_URL=... ATTACKER_KEY=... VICTIM_KEY=... \
  python3 run_attacks.py ../../.audit/stand.json -c memory-poisoning --json
```

`AttackResult.path_state` возвращает термины аудита:
`static_path_supported` (вживую не воспроизвелось) → `runtime_path_observed`
(опубликовано) → `control_violation_observed` (маркер дошёл до жертвы).

### Обобщить на другую систему

1. Реализуйте `AttackTarget` (4 метода: `principals`, `new_session`, `deliver`,
   `trigger_persist`, `observe`) под её ручки — это аналог профиля аудита.
2. Сценарии и таксономия (`attack_taxonomy.py`) не меняются.
3. Раннер тот же; `_make_target()` подменяется на ваш адаптер.

Что переносится: `target.py`, `scenarios/`, `run_attacks.py`, таксономия, оракул.
Что пишется под систему: `targets/<system>.py` + формулировки инъекций (данные).
