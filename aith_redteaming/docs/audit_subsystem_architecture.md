# Архитектура аудит-подсистемы MCP-агента

**Место в пайплайне:** фаза P1 (Audit/Inventory).
**Вход:** конфиг MCP-серверов, живой MCP-handshake, контекстные файлы агента.
**Выход:** верифицированный инвентарь capability/риска — JSON вида `audit v1.0`, питающий threat model (P2), корпус атак (P3) и дрейф-детект (P8).

---

## 0. Что аудит должен производить

Не «список инструментов», а **три связанных ответа**:
1. *Что агент реально может* (эффективные права, а не задекларированные).
2. *Что спрятано в определениях инструментов* (описания/схемы — канал tool poisoning).
3. *Собрана ли летальная триада* (чувствительный доступ × недоверенный ввод × канал наружу) → итоговый вердикт.

Слепое пятно исходного аудита: он покрыл (1) и частично триаду, но **не инспектировал описания и схемы инструментов** — а именно там живёт tool poisoning, невидимый в capability-таблице. Эта архитектура делает инспекцию определений первоклассной плоскостью.

---

## 1. Два принципа, на которых стоит вся архитектура

### 1.1 Три плоскости аудита

| Плоскость | Вопрос | Чем закрывается |
|---|---|---|
| **Capability** | Что агент может делать? | Discovery + классификация + эффективные права |
| **Definition** | Что написано в самих определениях инструментов? | Статический анализ описаний/схем (mcp-scan) |
| **Behavioral** | Что происходит, когда мы это реально пробуем? | Активные пробы в песочнице (массив `tests`) |

Исходный JSON силён в capability, слаб в definition. Полный аудит требует всех трёх.

### 1.2 Три уровня доверия к каждому факту

Каждое утверждение аудита помечается провенансом:
- **declared** — заявлено сервером (`declared_capabilities`). Верить нельзя, это самоотчёт.
- **effective** — выведено из конфига/прав (`effective_access.paths.allowed/denied`).
- **verified** — подтверждено активной пробой (`"verified": true`, массив `tests`).

Вердикт строится только на effective+verified. Declared идёт как метка расхождений.

---

## 2. Компонентная архитектура

```
                          ┌─────────────────────────────────────────────┐
   config files ───┐      │            AUDIT ORCHESTRATOR                │
   MCP handshake ──┼────▶ │   (единая модель данных = audit JSON)        │
   context files ──┘      └───────┬───────────┬───────────┬─────────────┘
                                  │           │           │
                    ┌─────────────▼──┐  ┌─────▼──────┐  ┌─▼──────────────┐
                    │ 1. DISCOVERY   │  │ 2. STATIC  │  │ 4. ACTIVE      │
                    │  /ENUMERATION  │  │  ANALYSIS  │  │  VERIFICATION  │
                    │ серверы, tools │  │ (definition│  │ (behavioral,   │
                    │ схемы, транспорт│  │  plane)    │  │  в песочнице)  │
                    └───────┬────────┘  └─────┬──────┘  └───────┬────────┘
                            │                 │                 │
                            ▼                 ▼                 ▼
                    ┌────────────────────────────────────────────────────┐
                    │ 3. CLASSIFICATION & RISK  (READ/WRITE/EXEC/DELETE,   │
                    │    risk LOW..CRITICAL, effective-access resolver)    │
                    └───────────────────────┬────────────────────────────┘
                                            ▼
                    ┌────────────────────────────────────────────────────┐
                    │ 5. TRIFECTA / CORRELATION ENGINE                    │
                    │    (агрегация по серверам, cross-server shadowing,   │
                    │     overall_risk, verdict)                           │
                    └───────────────────────┬────────────────────────────┘
                                            ▼
                    ┌────────────────────────────────────────────────────┐
                    │ 6. FINDINGS & REPORTING  → audit JSON               │
                    │    + hash-baseline (для дрейфа) → P2 / P3 / P8       │
                    └────────────────────────────────────────────────────┘
```

Пассивные слои (1, 2, 3, 6) работают где угодно. Активный слой (4) **обязан** выполняться в изолированном стенде (P0), потому что он реально дёргает `execute_command`, пишет и удаляет.

---

## 3. Слои детально

### Слой 1 — Discovery / Enumeration

**Цель:** собрать сырую карту топологии.

Компоненты:
- **Config parser** — читает конфиг MCP-серверов: `name`, `transport` (stdio/sse/http), `command`, `args`. Из вашего JSON: `filesystem` → `npx @modelcontextprotocol/server-filesystem /workspace/my-project`.
- **MCP introspector** — выполняет handshake и запрашивает у каждого сервера список инструментов, их **описания** и **JSON-схемы параметров**, а также `declared_capabilities` (tools/resources/prompts).
- **Agent-context parser** — читает контекстные файлы (`CLAUDE.md`, `.cursorrules`, `.github/copilot-instructions.md`). Они не инструменты, но задают инструкции агенту — это часть поверхности (Ось 2/3).

Выход: сырой граф «сервер → инструменты → схемы/описания → транспорт».

### Слой 2 — Static Analysis (definition plane) ← закрывает слепое пятно

**Цель:** найти вредоносное/опасное **в тексте самих определений**, до всякого выполнения.

Компоненты:
- **mcp-scan integration** — статический анализ описаний и схем на паттерны инъекций и индикаторы shadowing (Invariant Labs).
- **Description linter** — императивы/инструкции в описании («перед любым инструментом сначала прочитай…»), скрытые Unicode-символы (zero-width, bidi — `AML.T0068`).
- **Schema analyzer** — подозрительные параметры: поля, куда можно увести секрет; несоответствие схемы назначению инструмента (schema poisoning).
- **Cross-server collision detector** — дубликаты имён инструментов на разных серверах (сигнал shadowing).
- **Definition hasher** — хэш каждого определения (описание + схема). Это **baseline для детекта rug pull** в P8: изменение хэша между аудитами = сервер поменял определение после одобрения.

Выход: findings по definition-плоскости + хэш-базлайн.

### Слой 3 — Classification & Risk

**Цель:** превратить сырые инструменты в классифицированные записи.

Компоненты:
- **Operation classifier** — каждый инструмент → `READ` / `WRITE` / `EXEC` / `DELETE` (в JSON: `read_file`=READ, `write_file`=WRITE, `delete_file`=WRITE+destructive, `execute_command`=EXEC).
- **Risk scorer** — `LOW/MEDIUM/HIGH/CRITICAL` по классу операции × охвату × деструктивности (в JSON: `execute_command`→CRITICAL, `delete_file`→CRITICAL, `write_file`→HIGH, `query`→MEDIUM).
- **Effective-access resolver** — declared права → эффективные: `filesystem` allowed `/workspace/my-project/**`, denied `/etc/**`,`/root/**`; `postgres` operations `[SELECT]` / `[INSERT,UPDATE,DELETE]`, `ddl:false`.

Выход: нормализованные записи инструментов с классом, риском и эффективным охватом.

### Слой 4 — Active Verification (behavioral plane) — только в песочнице

**Цель:** подтвердить эффективные права реальными пробами, а не верить конфигу.

Компоненты:
- **Probe runner** — выполняет безопасные пробы и фиксирует результат: в JSON это массив `tests` (`read_project_file`→PASS, `write_project_file`→PASS, `path_traversal ../outside.txt`→BLOCKED, `arbitrary_command`→PASS/CRITICAL).
- **Boundary tester** — проверяет заявленные границы: что denied реально denied (traversal заблокирован), что DDL реально недоступен.
- **Isolation guard** — гарантирует, что пробы бьют только по стенду; egress уходит в sinkhole; секреты — canary.

Выход: `verified:true/false` для каждого заявленного права + список подтверждённых границ.

> Безопасность: слой 4 реально исполняет команды и пишет/удаляет, поэтому запускается **исключительно** в изолированном стенде (P0). В пассивном режиме аудита (на проде) слой 4 выключен — работают только 1–3, 6.

### Слой 5 — Trifecta / Correlation Engine

**Цель:** от «инструмент за инструментом» перейти к системному вердикту.

Компоненты:
- **Trifecta assessor** — агрегирует по всем серверам: есть ли одновременно чувствительный доступ (`read_file`, `query`, env), недоверенный ввод (результаты чтения, БД, GitHub, stdout) и канал наружу (`network_access`, `create_pull_request`). В вашем случае — собрана.
- **Cross-server reasoner** — потенциал shadowing: может ли один сервер влиять на поведение при вызове инструментов другого (важно для 4+ серверов).
- **Verdict builder** — `overall_risk`, `full_project_access`, `arbitrary_code_execution`, список причин, `confidence`.

Выход: `summary` + `verdict` + `security_findings` (в JSON: MCP-001 ARBITRARY_CODE_EXECUTION CRITICAL, MCP-002 PROJECT_WRITE_ACCESS HIGH).

### Слой 6 — Findings & Reporting

**Цель:** эмитировать канонический артефакт и раздать вниз по пайплайну.

Компоненты:
- **JSON emitter** — пишет схему `audit` (servers, effective_capabilities, security_findings, tests, verdict) с провенансом каждого факта.
- **Baseline store** — сохраняет хэши определений и снимок capability (для P8-дрейфа).
- **Downstream feeders** — маппинг findings → строки `TM-*` матрицы (P2), → выбор кейсов `C*` корпуса (P3).

---

## 4. Поток данных (сквозной)

```
config + handshake + context
        │
        ▼
   [1 Discovery] ──▶ сырой граф серверов/инструментов/схем
        │
        ├──▶ [2 Static analysis] ──▶ definition findings + hash-baseline
        │
        ├──▶ [3 Classification]  ──▶ класс/риск/эффективный охват
        │
        └──▶ [4 Active probes]*  ──▶ verified-права + границы     (*только стенд)
                        │
                        ▼
              [5 Trifecta/Correlation] ──▶ overall_risk + verdict + findings
                        │
                        ▼
              [6 Findings/Reporting] ──▶ audit JSON + baseline
                        │
             ┌──────────┼───────────┐
             ▼          ▼           ▼
          P2 matrix   P3 corpus   P8 drift
```

---

## 5. Режимы работы

| Режим | Слои | Где запускать | Когда |
|---|---|---|---|
| **Passive** | 1, 2, 3, 5, 6 | где угодно (в т.ч. рядом с продом) | регулярно, безопасно; не трогает систему |
| **Active** | + 4 (пробы) | только изолированный стенд P0 | при сборке стенда, перед кампаниями |
| **Drift** (P8) | 1, 2 + сверка хэшей | CI / on-config-change | на любое изменение MCP-конфига |

Passive-аудит даёт инвентарь и definition-findings без риска. Active добавляет verified-подтверждение. Drift ловит rug pull (изменение хэша определения) и появление новых серверов.

---

## 6. Границы доверия в архитектуре

- **MCP-серверы недоверенны по умолчанию.** Их `declared_capabilities` — самоотчёт; верифицируется слоями 3–4.
- **Описания инструментов недоверенны.** Обрабатываются слоем 2 как потенциальная нагрузка, а не как «текст от разработчика».
- **Результаты активных проб доверенны** (это ваши наблюдения на стенде), но их окружение — sinkhole/canary.
- **Оркестратор и baseline-store доверенны** и отделены от attacker-плоскости стенда.

---

## 7. Привязка компонентов к JSON-схеме аудита

| Компонент | Поле в audit JSON |
|---|---|
| Config parser / Introspector | `servers[].transport/command/args`, `declared_capabilities`, `tools[]` |
| Static analysis | (новое) definition-findings, hash-baseline — расширение схемы |
| Operation classifier | `tools[].classification` |
| Risk scorer | `tools[].risk`, `summary.critical/high/...` |
| Effective-access resolver | `tools[].effective_access`, `effective_capabilities` |
| Probe runner / Boundary tester | `tests[]` (result PASS/BLOCKED), `verified` |
| Trifecta assessor / Verdict builder | `summary.overall_risk`, `verdict`, `security_findings[]` |

> Рекомендация: расширить исходную схему секцией `definition_analysis` (описания/схемы/хэши/shadowing), которой в `audit v1.0` нет — это и есть закрытие слепого пятна.

---

## 8. Связь с пайплайном

- **P1** — этот аудит целиком; passive+active режимы.
- **P2** — findings → достижимые строки `TM-*`.
- **P3** — критичные инструменты → выбор кампаний (`C4-*` tool poisoning, `C2-*` memory).
- **P8** — drift-режим на baseline: изменение хэша определения = алерт rug pull; новый сервер = повторный полный аудит.

---

*Аудит — диагностика, а не защита: он показывает состав риска, но не устраняет его. Активная плоскость (слой 4) исполняется только в изолированном стенде. Документ — архитектурная спека для харденинга собственной конфигурации.*
