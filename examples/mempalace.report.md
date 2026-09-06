# Отчёт аудита безопасности агентной системы — mempalace-hub

## 1. Цель, версии, среда, режим и пределы оценки

- Цель: **mempalace-hub**, сборка: `d9f059076c866fa6f29195679d75712436986024`, среда: shared hub \(deploy/docker-compose.server.yml\)
- Режим: `offline`, профиль источников: `white_box`, run: `run-e7034994aa19`
- Версии: схема отчёта 2.0, движок 2.0.0, правила 2.0.0
- Runtime-проверки выполнялись: **нет**
- Состояние оценки: **partial**; вывод по безопасности: **findings\_present**
- ⚠ **Покрытие неполное**: не разрешённые контроли — MEM-06, MEM-08, MEM-10, AUTH-03, AUTH-05, AUTH-06, INFRA-01, TOOL-01, TOOL-02, TOOL-04, TOOL-05, INV-02; недоступные адаптеры — нет
- Уверенность: medium — 0 finding\(s\) runtime-supported, 11 static-supported; static support shows a code/config defect, not an observed effect on the running model

## 2. Наиболее важные подтверждённые выводы и приоритеты

| Приоритет | Серьёзность | Правило | Finding | Статус подтверждения |
|---|---|---|---|---|
| P0 | CRITICAL | AUTH-01 | Input identity taken from an untrusted field (`F-28ee3cf382`) | static_supported |
| P0 | CRITICAL | AUTH-02 | Resource authorization not enforced at mcp-server (`F-3a679d1101`) | static_supported |
| P0 | CRITICAL | AUTH-02 | Resource authorization not enforced at mcp-server (`F-30851f3d4a`) | static_supported |
| P0 | HIGH | MEM-01 | Personal memory read without audience binding (`F-7fa1b06531`) | static_supported |
| P0 | HIGH | MEM-03 | Memory owner / audience decided by an untrusted source (`F-0859ec7319`) | static_supported |
| P0 | HIGH | MEM-03 | Memory owner / audience decided by an untrusted source (`F-4cca5f00c0`) | static_supported |
| P0 | HIGH | MEM-03 | Memory owner / audience decided by an untrusted source (`F-3b61b48b62`) | static_supported |
| P1 | HIGH | MEM-07 | Retrieval returns records before audience policy is applied (`F-2a7047e051`) | static_supported |
| P1 | HIGH | AUTH-04 | mcp-server: token validation skips revocation, binding\_to\_principal (`F-27fb087bc2`) | static_supported |
| P1 | HIGH | EGRESS-01 | Uncontrolled transmission to peer-node (`F-51e532dfe9`) | static_supported |
| P2 | MEDIUM | MEM-09 | Background job J-mine lacks consistency guarantees (`F-5131603f15`) | static_supported |

Гипотезы, требующие разбора: 3 (перечислены в разделе 5 отдельно от подтверждённых).

## 3. Покрытие, недоступные источники и незавершённые проверки

| Адаптер | Вид | Версия | Статус | Причины |
|---|---|---|---|---|
| mcp-config | mcp_inventory | 2.0.0 | **available** |  |
| source | source_snapshot | 2.0.0 | **available** |  |
| policy | policy_snapshot | 2.0.0 | **available** |  |
| deployment | deployment | 2.0.0 | **available** |  |

| Метрика | Значение | Знаменатель | Неизвестно | Ограничение |
|---|---|---|---|---|
| inventory_completeness | 45/45 \(100.0%\) | reference inventory \(profile/policy\) | 0 | the reference list may itself be partial |
| component_coverage | 5/8 \(62.5%\) | components of manifest/profile/inventory | 0 | does not show the depth of evaluation per component |
| mandatory_control_coverage | 14/26 \(53.8%\) | required controls minus justified not-applicable | 12 | INCONCLUSIVE, NOT\_EVALUATED and unknown applicability stay in the denominator |
| mandatory_control_coverage_static | 14/26 \(53.8%\) | same as above | 0 | static support shows code/config facts, not runtime behaviour |
| mandatory_control_coverage_runtime | 0/26 \(0.0%\) | same as above | 0 | runtime support is bound to the observed principal, build and environment |
| identity_coverage | 1/3 \(33.3%\) | expected access relations in policy | 0 | not replaced by the number of tokens used; a verified transition is a static fact |
| memory_stage_W | не определено | applicable memory cases | 0 | stages are never merged into one verified |
| memory_stage_R | не определено | applicable memory cases | 0 | stages are never merged into one verified |
| memory_stage_C | не определено | applicable memory cases | 0 | stages are never merged into one verified |
| memory_stage_B | не определено | applicable memory cases | 0 | stages are never merged into one verified |
| boundary_coverage | 2/2 \(100.0%\) | boundaries of the accepted model | 0 | an unreached backend is not counted as evaluated |
| execution_quality | не определено | control cases | 0 | errors are not excluded to make the report look complete |
| observation_quality | не определено | no trace | 0 | no runtime observation available |

Незавершённые контроли:
- `MEM-06`: NOT_EVALUATED — no trust-elevation / approval flows and no shared records available
- `MEM-08`: NOT_EVALUATED — no revocation events; MEM-08 is a stage-D control \(roadmap: revocation fixtures\)
- `MEM-10`: INCONCLUSIVE — 
- `AUTH-03`: NOT_EVALUATED — no security-mode flows or client-weakening attributes declared
- `AUTH-05`: NOT_EVALUATED — no delegation attributes on transitions
- `AUTH-06`: NOT_EVALUATED — no revocation-check flows; stage D \(revocation traces on the roadmap\)
- `INFRA-01`: INCONCLUSIVE — 
- `TOOL-01`: NOT_EVALUATED — required source\(s\) not bound: \['baseline'\]
- `TOOL-02`: NOT_EVALUATED — only one definition source per tool; contracts cannot be compared
- `TOOL-04`: NOT_EVALUATED — no chain from tool results to policy/publication declared in the profile
- `TOOL-05`: INCONCLUSIVE — 3 text signal\(s\) recorded as hypotheses with fragment, rule and explanation; an imperative, Unicode or a link does not prove malicious intent - review required
- `INV-02`: NOT_EVALUATED — discovery not performed in this mode \(configured catalogue only\)

## 4. Карта компонентов и границ доверия

| Компонент | Тип | Роль | Источники инвентаря | Состояние знания |
|---|---|---|---|---|
| `server:mempalace` | mcp_server |  | configured, source\_defined, summary | known |
| `mcp-server` | mcp_server | external\_tool\_host | profile | assumed |
| `palace-store` | memory_store | memory\_store | profile | assumed |
| `knowledge-graph` | memory_store | memory\_store | profile | assumed |
| `logstream` | memory_store | memory\_store | profile | assumed |
| `miner` | background_job | background\_job | profile | assumed |
| `logsync` | background_job | background\_job | profile | assumed |
| `peer-node` | external_provider | external\_provider | profile | assumed |

| Граница | Откуда → куда | Правило | Точка исполнения | Наблюдение |
|---|---|---|---|---|
| `HB-hub` | agent → mcp-server | общий bearer-токен подтверждает подлинность, но не ограничивает объекты | \_http\_request\_rejected | not_observed |
| `HB-peer` | peer-node → logstream | пир применяет свои события в наш лог, ограничен только владением токеном | logsync.sync\_with\_peer | not_observed |

Рёбер графа: 11; состояния: memory\_write:static\_path\_supported, scope\_decision:static\_path\_supported, memory\_write:static\_path\_supported, scope\_decision:static\_path\_supported, memory\_read:static\_path\_supported, context\_include:static\_path\_supported, derivation:static\_path\_supported, memory\_write:static\_pa…

| Цепочка | Состояние | Условия |
|---|---|---|
| Событие пира → локальный лог → выдача агенту по to\_agent → контекст модели | **capability_combination** |  |

Индикатор LETHAL_TRIFECTA: **unknown** — Trifecta legs not all present; missing: \['external\_channel'\]

### Инвентарь

| Сервер | Источник каталога | Handshake | Инструмент | Класс | Операции | Риск возможности | Основание |
|---|---|---|---|---|---|---|---|
| mempalace | none | не выполнялся | `mempalace\_status` | READ | READ | HIGH | source_inference/assumed |
| mempalace | none | не выполнялся | `mempalace\_list\_wings` | READ | READ | HIGH | source_inference/assumed |
| mempalace | none | не выполнялся | `mempalace\_list\_rooms` | READ | READ | HIGH | source_inference/assumed |
| mempalace | none | не выполнялся | `mempalace\_get\_taxonomy` | READ | READ | HIGH | source_inference/assumed |
| mempalace | none | не выполнялся | `mempalace\_get\_aaak\_spec` | READ | READ | HIGH | source_inference/assumed |
| mempalace | none | не выполнялся | `mempalace\_kg\_query` | READ | READ | HIGH | source_inference/assumed |
| mempalace | none | не выполнялся | `mempalace\_kg\_add` | WRITE | CREATE | HIGH | source_inference/assumed |
| mempalace | none | не выполнялся | `mempalace\_kg\_invalidate` | WRITE | CREATE,UPDATE | HIGH | source_inference/assumed |
| mempalace | none | не выполнялся | `mempalace\_kg\_supersede` | WRITE | CREATE,UPDATE | HIGH | source_inference/assumed |
| mempalace | none | не выполнялся | `mempalace\_kg\_timeline` | READ | READ | HIGH | source_inference/assumed |
| mempalace | none | не выполнялся | `mempalace\_kg\_stats` | READ | READ | HIGH | source_inference/assumed |
| mempalace | none | не выполнялся | `mempalace\_traverse` | READ | READ | HIGH | source_inference/assumed |
| mempalace | none | не выполнялся | `mempalace\_find\_tunnels` | READ | READ | HIGH | source_inference/assumed |
| mempalace | none | не выполнялся | `mempalace\_graph\_stats` | READ | READ | HIGH | source_inference/assumed |
| mempalace | none | не выполнялся | `mempalace\_mesh\_peers` | READ | READ | HIGH | source_inference/assumed |
| mempalace | none | не выполнялся | `mempalace\_create\_tunnel` | WRITE | CREATE | HIGH | source_inference/assumed |
| mempalace | none | не выполнялся | `mempalace\_list\_tunnels` | READ | READ | HIGH | source_inference/assumed |
| mempalace | none | не выполнялся | `mempalace\_delete\_tunnel` | DELETE | DELETE | CRITICAL | source_inference/assumed |
| mempalace | none | не выполнялся | `mempalace\_list\_hallways` | READ | READ | HIGH | source_inference/assumed |
| mempalace | none | не выполнялся | `mempalace\_delete\_hallway` | DELETE | DELETE | CRITICAL | source_inference/assumed |
| mempalace | none | не выполнялся | `mempalace\_follow\_tunnels` | READ | READ | HIGH | source_inference/assumed |
| mempalace | none | не выполнялся | `mempalace\_search` | READ | READ | HIGH | source_inference/assumed |
| mempalace | none | не выполнялся | `mempalace\_check\_duplicate` | READ | READ | HIGH | source_inference/assumed |
| mempalace | none | не выполнялся | `mempalace\_add\_drawer` | WRITE | CREATE | HIGH | source_inference/assumed |
| mempalace | none | не выполнялся | `mempalace\_checkpoint` | WRITE | CREATE,UPDATE | HIGH | source_inference/assumed |
| mempalace | none | не выполнялся | `mempalace\_delete\_drawer` | DELETE | DELETE | CRITICAL | source_inference/assumed |
| mempalace | none | не выполнялся | `mempalace\_mine` | WRITE | CREATE,UPDATE | HIGH | declared/assumed |
| mempalace | none | не выполнялся | `mempalace\_delete\_by\_source` | DELETE | DELETE | CRITICAL | source_inference/assumed |
| mempalace | none | не выполнялся | `mempalace\_sync` | DELETE | DELETE,UPDATE | CRITICAL | declared/assumed |
| mempalace | none | не выполнялся | `mempalace\_get\_drawer` | READ | READ | HIGH | declared/assumed |
| mempalace | none | не выполнялся | `mempalace\_list\_drawers` | READ | READ | HIGH | source_inference/assumed |
| mempalace | none | не выполнялся | `mempalace\_update\_drawer` | WRITE | CREATE,UPDATE | HIGH | source_inference/assumed |
| mempalace | none | не выполнялся | `mempalace\_diary\_write` | WRITE | CREATE,UPDATE | HIGH | source_inference/assumed |
| mempalace | none | не выполнялся | `mempalace\_diary\_read` | READ | READ | HIGH | source_inference/assumed |
| mempalace | none | не выполнялся | `mempalace\_hook\_settings` | WRITE | CREATE,UPDATE | HIGH | source_inference/assumed |
| mempalace | none | не выполнялся | `mempalace\_memories\_filed\_away` | WRITE | CREATE,UPDATE | HIGH | source_inference/assumed |
| mempalace | none | не выполнялся | `mempalace\_reconnect` | WRITE | UPDATE | HIGH | declared/assumed |
| mempalace | none | не выполнялся | `mempalace\_event\_append` | WRITE | CREATE | HIGH | declared/assumed |
| mempalace | none | не выполнялся | `mempalace\_task\_create` | WRITE | CREATE | HIGH | declared/assumed |
| mempalace | none | не выполнялся | `mempalace\_event\_list` | READ | READ | HIGH | source_inference/assumed |
| mempalace | none | не выполнялся | `mempalace\_event\_wait` | READ | READ | HIGH | declared/assumed |
| mempalace | none | не выполнялся | `mempalace\_event\_ack` | WRITE | CREATE,UPDATE | HIGH | source_inference/assumed |
| mempalace | none | не выполнялся | `mempalace\_artifact\_put` | WRITE | CREATE,UPDATE | HIGH | source_inference/assumed |
| mempalace | none | не выполнялся | `mempalace\_artifact\_get` | READ | READ | HIGH | declared/assumed |
| mempalace | none | не выполнялся | `mempalace\_patch\_submit` | WRITE | CREATE,UPDATE | HIGH | source_inference/assumed |

## 5. Findings: основания и критерии закрытия

### 5.1 Подтверждённые (static_supported / runtime_supported)

- **[CRITICAL (подтверждено: static_supported)] AUTH-01 `F-28ee3cf382` `IDENTITY_FROM_UNTRUSTED_FIELD`** — Input identity taken from an untrusted field
  - mcp-server establishes the principal from body\_field.
  - Наблюдаемый эффект: не наблюдался; возможный эффект: -
  - Основания: claims CL-AUTH-01-F-agent-identity; evidence E-b501815379
  - Исправление: derive the principal from authentication only; ignore body fields and conversation text Критерий закрытия: request body / conversation cannot override the authenticated principal \(fixture\)
- **[CRITICAL (подтверждено: static_supported)] AUTH-02 `F-3a679d1101` `RESOURCE_AUTHORIZATION_MISSING`** — Resource authorization not enforced at mcp-server
  - agent -\> mcp-server -\> \* palace\(любой ящик, событие, артефакт\): decision not\_enforced; conditions: \['hub-режим: один токен на все клиентские подключения'\].
  - Предпосылки: hub-режим: один токен на все клиентские подключения
  - Наблюдаемый эффект: не наблюдался; возможный эффект: a valid token grants access to any object \(IDOR / BAC delegated to the model\)
  - Основания: claims CL-AUTH-02-AT-hub-tools; evidence E-aa6e6fe131
  - Исправление: check subject -\> object permission at this hop, including client -\> account -\> operation relations Критерий закрытия: each receiving service decides authorization for the concrete object; foreign-object fixture is refused at this hop
  - Ограничения: an entry-API refusal does not cover a backend the request never reached
- **[CRITICAL (подтверждено: static_supported)] AUTH-02 `F-30851f3d4a` `RESOURCE_AUTHORIZATION_MISSING`** — Resource authorization not enforced at mcp-server
  - peer-node -\> mcp-server -\> READ logstream\(любой origin\): decision not\_enforced; conditions: none.
  - Наблюдаемый эффект: не наблюдался; возможный эффект: a valid token grants access to any object \(IDOR / BAC delegated to the model\)
  - Основания: claims CL-AUTH-02-AT-sync-pull; evidence E-229951f3ed
  - Исправление: check subject -\> object permission at this hop, including client -\> account -\> operation relations Критерий закрытия: each receiving service decides authorization for the concrete object; foreign-object fixture is refused at this hop
  - Ограничения: an entry-API refusal does not cover a backend the request never reached
- **[HIGH (подтверждено: static_supported)] MEM-01 `F-7fa1b06531` `MEMORY_ISOLATION_MISSING`** — Personal memory read without audience binding
  - logstream reads memory type 'event' \(audience agent\) without binding the query to the requesting subject.
  - Наблюдаемый эффект: не наблюдался; возможный эффект: cross-subject memory disclosure
  - Основания: claims CL-MEM-01-F-event-read; evidence E-153c73168a
  - Исправление: bind every retrieval to the authenticated subject / allowed audience Критерий закрытия: retrieval paths for personal types carry an audience filter; fixture read for another subject returns nothing
  - Ограничения: scope/tenant fields in a document do not prove access control enforcement
- **[HIGH (подтверждено: static_supported)] MEM-03 `F-0859ec7319` `SCOPE_DECIDED_BY_UNTRUSTED_SOURCE`** — Memory owner / audience decided by an untrusted source
  - mcp-server takes the audience of 'drawer' from client; validation: sanitize\_name/sanitize\_content — синтаксическая нормализация, не решение о владельце.
  - Наблюдаемый эффект: не наблюдался; возможный эффект: metadata produced by a model or external content sets write authority
  - Основания: claims CL-MEM-03-F-drawer-scope; evidence E-05fc8a138e
  - Исправление: resolve owner and audience server-side from the authenticated principal and policy Критерий закрытия: proposed scope from model/external content is advisory only; the server decides
- **[HIGH (подтверждено: static_supported)] MEM-03 `F-4cca5f00c0` `SCOPE_DECIDED_BY_UNTRUSTED_SOURCE`** — Memory owner / audience decided by an untrusted source
  - mcp-server takes the audience of 'event' from client; validation: \_sanitize\_routing — проверка формата идентификатора, не проверка прав.
  - Наблюдаемый эффект: не наблюдался; возможный эффект: metadata produced by a model or external content sets write authority
  - Основания: claims CL-MEM-03-F-event-scope; evidence E-b501815379
  - Исправление: resolve owner and audience server-side from the authenticated principal and policy Критерий закрытия: proposed scope from model/external content is advisory only; the server decides
- **[HIGH (подтверждено: static_supported)] MEM-03 `F-3b61b48b62` `SCOPE_DECIDED_BY_UNTRUSTED_SOURCE`** — Memory owner / audience decided by an untrusted source
  - peer-node takes the audience of 'event' from peer; validation: none.
  - Наблюдаемый эффект: не наблюдался; возможный эффект: metadata produced by a model or external content sets write authority
  - Основания: claims CL-MEM-03-F-peer-scope; evidence E-1f0a715dc0
  - Исправление: resolve owner and audience server-side from the authenticated principal and policy Критерий закрытия: proposed scope from model/external content is advisory only; the server decides
- **[HIGH (подтверждено: static_supported)] MEM-07 `F-2a7047e051` `RETRIEVAL_WITHOUT_AUDIENCE_FILTER`** — Retrieval returns records before audience policy is applied
  - logstream: Чтение событий фильтруется параметром to\_agent, который выбирает сам вызывающий: привязки к аутентифицированному агенту нет..
  - Наблюдаемый эффект: не наблюдался; возможный эффект: -
  - Основания: claims CL-MEM-07-F-event-read; evidence E-153c73168a
  - Исправление: apply audience filtering in the query / index partition, before ranking and context assembly Критерий закрытия: retrieval, cache keys and index partitions include the audience; fixture retrieval for a foreign audience is empty
- **[HIGH (подтверждено: static_supported)] AUTH-04 `F-27fb087bc2` `TOKEN_VALIDATION_INCOMPLETE`** — mcp-server: token validation skips revocation, binding\_to\_principal
  - scheme api\_key requires \['lookup', 'revocation', 'binding\_to\_principal'\]; observed \{'lookup': True, 'revocation': False, 'binding\_to\_principal': False\}.
  - Наблюдаемый эффект: не наблюдался; возможный эффект: a token issued for another audience/issuer is accepted by this service
  - Основания: claims CL-AUTH-04-mcp-server; evidence E-aa6e6fe131
  - Исправление: validate issuer, audience, signature, expiry and algorithm against trusted config of this service Критерий закрытия: each receiving service rejects tokens with a foreign issuer/audience \(fixture\)
- **[HIGH (подтверждено: static_supported)] EGRESS-01 `F-51e532dfe9` `EGRESS_DATA_CATEGORY_UNCONTROLLED`** — Uncontrolled transmission to peer-node
  - destination peer-node allowed, but categories \['artifact\_content', 'patch'\] can be transmitted without a filter.
  - Наблюдаемый эффект: не наблюдался; возможный эффект: client identifiers or portfolio data reach an external provider inside a query
  - Основания: claims CL-EGRESS-01-F-sync-egress; evidence E-229951f3ed
  - Исправление: control both destination and data category; filter model-composed queries before transmission Критерий закрытия: egress policy is enforced for destination and category; fixture observes the actual payload locally
- **[MEDIUM (подтверждено: static_supported)] MEM-09 `F-5131603f15` `BACKGROUND_JOB_CONSISTENCY`** — Background job J-mine lacks consistency guarantees
  - miner: does not carry the originating identity.
  - Наблюдаемый эффект: не наблюдался; возможный эффект: -
  - Основания: claims CL-MEM-09-J-mine; evidence E-55e5e8b756
  - Исправление: carry job/parent ids, idempotency keys and the policy revision through background processing Критерий закрытия: retries, concurrent sessions and delayed jobs keep the original identity and skip cancelled data \(fixture\)
  - Ограничения: stage D: runtime job events \(job ids, parent ids\) are on the roadmap

### 5.2 Гипотезы и сигналы (требуют разбора; не являются подтверждённым нарушением)

- **[потенциально HIGH (гипотеза: hypothesis)] TOOL-05 `F-bb3b859f8f` `SINK_PARAMETER`** (mempalace/mempalace\_search) — Free-form sink parameter
  - mempalace\_search.context is a free-form field a poisoned description can route data into
  - Ограничения: schema heuristic: a hypothesis about misuse potential, not an observed abuse
- **[потенциально HIGH (гипотеза: hypothesis)] TOOL-05 `F-ee211a9ca0` `SINK_PARAMETER`** (mempalace/mempalace\_event\_append) — Free-form sink parameter
  - mempalace\_event\_append.metadata is a free-form field a poisoned description can route data into
  - Ограничения: schema heuristic: a hypothesis about misuse potential, not an observed abuse
- **[потенциально MEDIUM (гипотеза: hypothesis)] TOOL-05 `F-b64b82e14e` `MODEL_ADDRESSED_IMPERATIVE`** (mempalace/mempalace\_get\_aaak\_spec) — Imperative addressed to the model
  - Imperative addressed to the model in description: 'you need to'
  - Ограничения: text heuristic: the signal is a hypothesis, not proof of compromise or of a right to change the server

## 6. Результаты памяти по стадиям W/R/C/B

Стадийные наблюдения памяти не проводились (нет случаев/трасс): W/R/C/B = not_evaluated.

| Правило | Применимость | Выполнение | Исход | Интерпретация |
|---|---|---|---|---|
| MEM-01 | applicable | completed | **FAIL** |  |
| MEM-02 | applicable | completed | **PASS** | no publication path from user-session processing is declared or found |
| MEM-03 | applicable | completed | **FAIL** |  |
| MEM-04 | applicable | completed | **PASS** |  |
| MEM-05 | applicable | completed | **PASS** |  |
| MEM-06 | applicable | skipped | **NOT_EVALUATED** | no trust-elevation / approval flows and no shared records available |
| MEM-07 | applicable | completed | **FAIL** |  |
| MEM-08 | applicable | skipped | **NOT_EVALUATED** | no revocation events; MEM-08 is a stage-D control \(roadmap: revocation fixtures\) |
| MEM-09 | applicable | completed | **FAIL** |  |
| MEM-10 | applicable | completed | **INCONCLUSIVE** |  |

## 7. Результаты авторизации и исходящих эффектов

| Правило | Применимость | Выполнение | Исход | Границы | Интерпретация |
|---|---|---|---|---|---|
| AUTH-01 | applicable | completed | **FAIL** |  |  |
| AUTH-02 | applicable | completed | **FAIL** | HB-hub, HB-peer | each hop evaluated separately; a refusal at one hop does not cover the next |
| AUTH-03 | applicable | skipped | **NOT_EVALUATED** |  | no security-mode flows or client-weakening attributes declared |
| AUTH-04 | applicable | completed | **FAIL** |  |  |
| AUTH-05 | applicable | skipped | **NOT_EVALUATED** |  | no delegation attributes on transitions |
| AUTH-06 | applicable | skipped | **NOT_EVALUATED** |  | no revocation-check flows; stage D \(revocation traces on the roadmap\) |
| INFRA-01 | applicable | completed | **INCONCLUSIVE** |  |  |
| INFRA-02 | applicable | completed | **PASS** |  | bind, publication, routing and filtering are separate facts; only publication is observed here |
| INFRA-03 | not_applicable | skipped | **NOT_APPLICABLE** |  | no controlled validation in this mode |
| TOOL-01 | applicable | skipped | **NOT_EVALUATED** |  | required source\(s\) not bound: \['baseline'\] |
| TOOL-02 | applicable | skipped | **NOT_EVALUATED** |  | only one definition source per tool; contracts cannot be compared |
| TOOL-03 | applicable | completed | **PASS** |  | router namespace: qualified; 0 name collision\(s\) |
| TOOL-04 | applicable | skipped | **NOT_EVALUATED** |  | no chain from tool results to policy/publication declared in the profile |
| TOOL-05 | applicable | completed | **INCONCLUSIVE** |  | 3 text signal\(s\) recorded as hypotheses with fragment, rule and explanation; an imperative, Unicode or a link does not prove malicious intent - review required |
| EGRESS-01 | applicable | completed | **FAIL** |  |  |
| EGRESS-02 | not_applicable | skipped | **NOT_APPLICABLE** |  | no controlled validation in this mode |
| INV-01 | applicable | completed | **PASS** |  |  |
| INV-02 | applicable | skipped | **NOT_EVALUATED** |  | discovery not performed in this mode \(configured catalogue only\) |

## 8. Изменения относительно совместимого baseline

Baseline не задан; сравнение не выполнялось.

## 9. План исправлений, повторная оценка и ограничения

| Приоритет | Finding | Исправление | Критерий закрытия |
|---|---|---|---|
| P0 | `F-28ee3cf382` | derive the principal from authentication only; ignore body fields and conversation text | request body / conversation cannot override the authenticated principal \(fixture\) |
| P0 | `F-3a679d1101` | check subject -\> object permission at this hop, including client -\> account -\> operation relations | each receiving service decides authorization for the concrete object; foreign-object fixture is refused at this hop |
| P0 | `F-30851f3d4a` | check subject -\> object permission at this hop, including client -\> account -\> operation relations | each receiving service decides authorization for the concrete object; foreign-object fixture is refused at this hop |
| P0 | `F-7fa1b06531` | bind every retrieval to the authenticated subject / allowed audience | retrieval paths for personal types carry an audience filter; fixture read for another subject returns nothing |
| P0 | `F-0859ec7319` | resolve owner and audience server-side from the authenticated principal and policy | proposed scope from model/external content is advisory only; the server decides |
| P0 | `F-4cca5f00c0` | resolve owner and audience server-side from the authenticated principal and policy | proposed scope from model/external content is advisory only; the server decides |
| P0 | `F-3b61b48b62` | resolve owner and audience server-side from the authenticated principal and policy | proposed scope from model/external content is advisory only; the server decides |
| P1 | `F-2a7047e051` | apply audience filtering in the query / index partition, before ranking and context assembly | retrieval, cache keys and index partitions include the audience; fixture retrieval for a foreign audience is empty |
| P1 | `F-27fb087bc2` | validate issuer, audience, signature, expiry and algorithm against trusted config of this service | each receiving service rejects tokens with a foreign issuer/audience \(fixture\) |
| P1 | `F-51e532dfe9` | control both destination and data category; filter model-composed queries before transmission | egress policy is enforced for destination and category; fixture observes the actual payload locally |
| P2 | `F-5131603f15` | carry job/parent ids, idempotency keys and the policy revision through background processing | retries, concurrent sessions and delayed jobs keep the original identity and skip cancelled data \(fixture\) |

Ограничения оценки:
- MEM-06: NOT\_EVALUATED \(no trust-elevation / approval flows and no shared records available\)
- MEM-08: NOT\_EVALUATED \(no revocation events; MEM-08 is a stage-D control \(roadmap: revocation fixtures\)\)
- MEM-10: INCONCLUSIVE \(\)
- AUTH-03: NOT\_EVALUATED \(no security-mode flows or client-weakening attributes declared\)
- AUTH-05: NOT\_EVALUATED \(no delegation attributes on transitions\)
- AUTH-06: NOT\_EVALUATED \(no revocation-check flows; stage D \(revocation traces on the roadmap\)\)
- INFRA-01: INCONCLUSIVE \(\)
- TOOL-01: NOT\_EVALUATED \(required source\(s\) not bound: \['baseline'\]\)
- TOOL-02: NOT\_EVALUATED \(only one definition source per tool; contracts cannot be compared\)
- TOOL-04: NOT\_EVALUATED \(no chain from tool results to policy/publication declared in the profile\)
- TOOL-05: INCONCLUSIVE \(3 text signal\(s\) recorded as hypotheses with fragment, rule and explanation; an imperative, Unicode or a link does not prove malicious intent - review required\)
- INV-02: NOT\_EVALUATED \(discovery not performed in this mode \(configured catalogue only\)\)
- no runtime validation was performed: all supported claims are static \(config, definitions, source, policy\)

## 10. Реестр свидетельств и версий правил

Свидетельств: 103; утверждений: 112; правила: 2.0.0

| ID | Источник | Метод | Локатор | Ограничения |
|---|---|---|---|---|
| `E-3458250d56` | config | parsing | path=examples/mempalace.config.json, kind=mcp\_config |  |
| `E-05fc8a138e` | source_code | static_analysis | path=mempalace/mcp\_server.py, symbol=tool\_add\_drawer, lines=\[3150, 3285\] |  |
| `E-b501815379` | source_code | static_analysis | path=mempalace/mcp\_server.py, symbol=tool\_event\_append, lines=\[4829, 4865\] |  |
| `E-153c73168a` | source_code | static_analysis | path=mempalace/mcp\_server.py, symbol=tool\_event\_list, lines=\[4921, 4967\] |  |
| `E-dbd4717bdb` | source_code | static_analysis | path=mempalace/mcp\_server.py, symbol=tool\_search, lines=\[2457, 2611\] |  |
| `E-2f84c72bce` | source_code | static_analysis | path=mempalace/miner.py, symbol=\_build\_drawer\_metadata, lines=\[1399, 1459\] |  |
| `E-1f0a715dc0` | source_code | static_analysis | path=mempalace/logsync.py, symbol=sync\_with\_peer, lines=\[51, 119\] |  |
| `E-229951f3ed` | source_code | static_analysis | path=mempalace/mcp\_server.py, symbol=\_http\_serve\_sync, lines=\[7701, 7751\] |  |
| `E-aa6e6fe131` | source_code | static_analysis | path=mempalace/mcp\_server.py, symbol=\_http\_request\_rejected, lines=\[7612, 7632\] |  |
| `E-55e5e8b756` | source_code | static_analysis | path=mempalace/miner.py, symbol=mine, lines=\[1844, 1898\] |  |
| `E-ede8c333ba` | source_code | static_analysis | path=mempalace/mcp\_server.py, symbol=TOOLS\['mempalace\_status'\], lines=\[5094, 5098\], declaration=mempalace\_status |  |
| `E-0a9b61161d` | source_code | static_analysis | path=mempalace/mcp\_server.py, symbol=TOOLS\['mempalace\_list\_wings'\], lines=\[5099, 5103\], declaration=mempalace\_li… |  |
| `E-a3a38ea9bf` | source_code | static_analysis | path=mempalace/mcp\_server.py, symbol=TOOLS\['mempalace\_list\_rooms'\], lines=\[5104, 5113\], declaration=mempalace\_li… |  |
| `E-831e0287b4` | source_code | static_analysis | path=mempalace/mcp\_server.py, symbol=TOOLS\['mempalace\_get\_taxonomy'\], lines=\[5114, 5118\], declaration=mempalace\_… |  |
| `E-e4c970818b` | source_code | static_analysis | path=mempalace/mcp\_server.py, symbol=TOOLS\['mempalace\_get\_aaak\_spec'\], lines=\[5119, 5123\], declaration=mempalace… |  |
| `E-bd6f44502f` | source_code | static_analysis | path=mempalace/mcp\_server.py, symbol=TOOLS\['mempalace\_kg\_query'\], lines=\[5124, 5145\], declaration=mempalace\_kg\_… |  |
| `E-8478ba8d95` | source_code | static_analysis | path=mempalace/mcp\_server.py, symbol=TOOLS\['mempalace\_kg\_add'\], lines=\[5146, 5181\], declaration=mempalace\_kg\_ad… |  |
| `E-bc81a23f3e` | source_code | static_analysis | path=mempalace/mcp\_server.py, symbol=TOOLS\['mempalace\_kg\_invalidate'\], lines=\[5182, 5198\], declaration=mempalace\… |  |
| `E-3887e02a6e` | source_code | static_analysis | path=mempalace/mcp\_server.py, symbol=TOOLS\['mempalace\_kg\_supersede'\], lines=\[5199, 5219\], declaration=mempalace\_… |  |
| `E-d670f154ff` | source_code | static_analysis | path=mempalace/mcp\_server.py, symbol=TOOLS\['mempalace\_kg\_timeline'\], lines=\[5220, 5232\], declaration=mempalace\_k… |  |
| `E-07f473c1ad` | source_code | static_analysis | path=mempalace/mcp\_server.py, symbol=TOOLS\['mempalace\_kg\_stats'\], lines=\[5233, 5237\], declaration=mempalace\_kg\_… |  |
| `E-e98c3bb4d9` | source_code | static_analysis | path=mempalace/mcp\_server.py, symbol=TOOLS\['mempalace\_traverse'\], lines=\[5238, 5255\], declaration=mempalace\_trave… |  |
| `E-1c6c7a6a97` | source_code | static_analysis | path=mempalace/mcp\_server.py, symbol=TOOLS\['mempalace\_find\_tunnels'\], lines=\[5256, 5266\], declaration=mempalace\_… |  |
| `E-5d211a6b8c` | source_code | static_analysis | path=mempalace/mcp\_server.py, symbol=TOOLS\['mempalace\_graph\_stats'\], lines=\[5267, 5271\], declaration=mempalace\_g… |  |
| `E-32eb6f0523` | source_code | static_analysis | path=mempalace/mcp\_server.py, symbol=TOOLS\['mempalace\_mesh\_peers'\], lines=\[5272, 5276\], declaration=mempalace\_me… |  |
| `E-a933381b0c` | source_code | static_analysis | path=mempalace/mcp\_server.py, symbol=TOOLS\['mempalace\_create\_tunnel'\], lines=\[5277, 5299\], declaration=mempalace\… |  |
| `E-96b1ba85ef` | source_code | static_analysis | path=mempalace/mcp\_server.py, symbol=TOOLS\['mempalace\_list\_tunnels'\], lines=\[5300, 5312\], declaration=mempalace\_… |  |
| `E-e85d95a18c` | source_code | static_analysis | path=mempalace/mcp\_server.py, symbol=TOOLS\['mempalace\_delete\_tunnel'\], lines=\[5313, 5323\], declaration=mempalace\… |  |
| `E-d25725d0e1` | source_code | static_analysis | path=mempalace/mcp\_server.py, symbol=TOOLS\['mempalace\_list\_hallways'\], lines=\[5324, 5336\], declaration=mempalace\… |  |
| `E-a792659006` | source_code | static_analysis | path=mempalace/mcp\_server.py, symbol=TOOLS\['mempalace\_delete\_hallway'\], lines=\[5337, 5347\], declaration=mempalace… |  |
| `E-1546d6c793` | source_code | static_analysis | path=mempalace/mcp\_server.py, symbol=TOOLS\['mempalace\_follow\_tunnels'\], lines=\[5348, 5359\], declaration=mempalace… |  |
| `E-3c1620c0fd` | source_code | static_analysis | path=mempalace/mcp\_server.py, symbol=TOOLS\['mempalace\_search'\], lines=\[5360, 5424\], declaration=mempalace\_search |  |
| `E-373994b5b4` | source_code | static_analysis | path=mempalace/mcp\_server.py, symbol=TOOLS\['mempalace\_check\_duplicate'\], lines=\[5425, 5439\], declaration=mempalac… |  |
| `E-ebf5d529e5` | source_code | static_analysis | path=mempalace/mcp\_server.py, symbol=TOOLS\['mempalace\_add\_drawer'\], lines=\[5440, 5460\], declaration=mempalace\_ad… |  |
| `E-142830ddda` | source_code | static_analysis | path=mempalace/mcp\_server.py, symbol=TOOLS\['mempalace\_checkpoint'\], lines=\[5461, 5510\], declaration=mempalace\_che… |  |
| `E-a812da4a04` | source_code | static_analysis | path=mempalace/mcp\_server.py, symbol=TOOLS\['mempalace\_delete\_drawer'\], lines=\[5511, 5521\], declaration=mempalace\… |  |
| `E-80d9ee30fd` | source_code | static_analysis | path=mempalace/mcp\_server.py, symbol=TOOLS\['mempalace\_mine'\], lines=\[5522, 5576\], declaration=mempalace\_mine |  |
| `E-392b9f6311` | source_code | static_analysis | path=mempalace/mcp\_server.py, symbol=TOOLS\['mempalace\_delete\_by\_source'\], lines=\[5577, 5594\], declaration=mempal… |  |
| `E-9533c2fe7f` | source_code | static_analysis | path=mempalace/mcp\_server.py, symbol=TOOLS\['mempalace\_sync'\], lines=\[5595, 5612\], declaration=mempalace\_sync |  |
| `E-95864d861a` | source_code | static_analysis | path=mempalace/mcp\_server.py, symbol=TOOLS\['mempalace\_get\_drawer'\], lines=\[5613, 5623\], declaration=mempalace\_ge… |  |
| `E-df3dfef943` | source_code | static_analysis | path=mempalace/mcp\_server.py, symbol=TOOLS\['mempalace\_list\_drawers'\], lines=\[5624, 5653\], declaration=mempalace\_… |  |
| `E-bc096d1cc1` | source_code | static_analysis | path=mempalace/mcp\_server.py, symbol=TOOLS\['mempalace\_update\_drawer'\], lines=\[5654, 5676\], declaration=mempalace\… |  |
| `E-52c2e0da83` | source_code | static_analysis | path=mempalace/mcp\_server.py, symbol=TOOLS\['mempalace\_diary\_write'\], lines=\[5677, 5709\], declaration=mempalace\_d… |  |
| `E-ecdbf16e59` | source_code | static_analysis | path=mempalace/mcp\_server.py, symbol=TOOLS\['mempalace\_diary\_read'\], lines=\[5710, 5731\], declaration=mempalace\_di… |  |
| `E-0fe4ef3623` | source_code | static_analysis | path=mempalace/mcp\_server.py, symbol=TOOLS\['mempalace\_hook\_settings'\], lines=\[5732, 5752\], declaration=mempalace\… |  |
| `E-7473b6833a` | source_code | static_analysis | path=mempalace/mcp\_server.py, symbol=TOOLS\['mempalace\_memories\_filed\_away'\], lines=\[5753, 5757\], declaration=mem… |  |
| `E-8c00962e30` | source_code | static_analysis | path=mempalace/mcp\_server.py, symbol=TOOLS\['mempalace\_reconnect'\], lines=\[5758, 5768\], declaration=mempalace\_reco… |  |
| `E-de8419da37` | source_code | static_analysis | path=mempalace/mcp\_server.py, symbol=TOOLS\['mempalace\_event\_append'\], lines=\[5769, 5832\], declaration=mempalace\_… |  |
| `E-096bbd46c8` | source_code | static_analysis | path=mempalace/mcp\_server.py, symbol=TOOLS\['mempalace\_task\_create'\], lines=\[5833, 5871\], declaration=mempalace\_t… |  |
| `E-ca16a72de5` | source_code | static_analysis | path=mempalace/mcp\_server.py, symbol=TOOLS\['mempalace\_event\_list'\], lines=\[5872, 5938\], declaration=mempalace\_ev… |  |
| `E-4327b463aa` | source_code | static_analysis | path=mempalace/mcp\_server.py, symbol=TOOLS\['mempalace\_event\_wait'\], lines=\[5939, 5989\], declaration=mempalace\_ev… |  |
| `E-2fd7771047` | source_code | static_analysis | path=mempalace/mcp\_server.py, symbol=TOOLS\['mempalace\_event\_ack'\], lines=\[5990, 6016\], declaration=mempalace\_eve… |  |
| `E-010356d2d0` | source_code | static_analysis | path=mempalace/mcp\_server.py, symbol=TOOLS\['mempalace\_artifact\_put'\], lines=\[6017, 6039\], declaration=mempalace\_… |  |
| `E-f4a97403f0` | source_code | static_analysis | path=mempalace/mcp\_server.py, symbol=TOOLS\['mempalace\_artifact\_get'\], lines=\[6040, 6052\], declaration=mempalace\_… |  |
| `E-fa6695603f` | source_code | static_analysis | path=mempalace/mcp\_server.py, symbol=TOOLS\['mempalace\_patch\_submit'\], lines=\[6053, 6085\], declaration=mempalace\_… |  |
| `E-84861b1d1c` | policy_snapshot | policy_inspection | path=examples/mempalace.policy.json, policy\_id=mempalace-hub-expected, version=1.0.0 | declared expectations; not evidence of enforcement |
| `E-14ab73c568` | deployment_snapshot | parsing | path=examples/mempalace.deployment.json, service=qdrant | bind/publication only; reachability per network zone not established |
| `E-337de37d0b` | deployment_snapshot | parsing | path=examples/mempalace.deployment.json, service=mempalace | bind/publication only; reachability per network zone not established |
| `E-111b622e43` | definition | parsing | server=mempalace, tool=mempalace\_status, inventory=none | definition text is untrusted self-report |
| `E-885a03f55f` | definition | parsing | server=mempalace, tool=mempalace\_list\_wings, inventory=none | definition text is untrusted self-report |
| `E-d4f5c7a1c1` | definition | parsing | server=mempalace, tool=mempalace\_list\_rooms, inventory=none | definition text is untrusted self-report |
| `E-c958dd97b2` | definition | parsing | server=mempalace, tool=mempalace\_get\_taxonomy, inventory=none | definition text is untrusted self-report |
| `E-b82bd21ccf` | definition | parsing | server=mempalace, tool=mempalace\_get\_aaak\_spec, inventory=none | definition text is untrusted self-report |
| `E-36bb2be1f7` | definition | parsing | server=mempalace, tool=mempalace\_kg\_query, inventory=none | definition text is untrusted self-report |
| `E-050806f108` | definition | parsing | server=mempalace, tool=mempalace\_kg\_add, inventory=none | definition text is untrusted self-report |
| `E-05f0248845` | definition | parsing | server=mempalace, tool=mempalace\_kg\_invalidate, inventory=none | definition text is untrusted self-report |
| `E-1e061de790` | definition | parsing | server=mempalace, tool=mempalace\_kg\_supersede, inventory=none | definition text is untrusted self-report |
| `E-a8df5f4a65` | definition | parsing | server=mempalace, tool=mempalace\_kg\_timeline, inventory=none | definition text is untrusted self-report |
| `E-d682bd9ab3` | definition | parsing | server=mempalace, tool=mempalace\_kg\_stats, inventory=none | definition text is untrusted self-report |
| `E-9e79252d75` | definition | parsing | server=mempalace, tool=mempalace\_traverse, inventory=none | definition text is untrusted self-report |
| `E-63664da675` | definition | parsing | server=mempalace, tool=mempalace\_find\_tunnels, inventory=none | definition text is untrusted self-report |
| `E-5fa77e2e78` | definition | parsing | server=mempalace, tool=mempalace\_graph\_stats, inventory=none | definition text is untrusted self-report |
| `E-384b199eb9` | definition | parsing | server=mempalace, tool=mempalace\_mesh\_peers, inventory=none | definition text is untrusted self-report |
| `E-bf44c1e48f` | definition | parsing | server=mempalace, tool=mempalace\_create\_tunnel, inventory=none | definition text is untrusted self-report |
| `E-292838ed9a` | definition | parsing | server=mempalace, tool=mempalace\_list\_tunnels, inventory=none | definition text is untrusted self-report |
| `E-a8a7cffa5a` | definition | parsing | server=mempalace, tool=mempalace\_delete\_tunnel, inventory=none | definition text is untrusted self-report |
| `E-f95e8a1dd0` | definition | parsing | server=mempalace, tool=mempalace\_list\_hallways, inventory=none | definition text is untrusted self-report |
| `E-c54306c2e0` | definition | parsing | server=mempalace, tool=mempalace\_delete\_hallway, inventory=none | definition text is untrusted self-report |
| `E-af57cd34f0` | definition | parsing | server=mempalace, tool=mempalace\_follow\_tunnels, inventory=none | definition text is untrusted self-report |
| `E-655cc4f69a` | definition | parsing | server=mempalace, tool=mempalace\_search, inventory=none | definition text is untrusted self-report |
| `E-fca76bb20d` | definition | parsing | server=mempalace, tool=mempalace\_check\_duplicate, inventory=none | definition text is untrusted self-report |
| `E-eed1f33da9` | definition | parsing | server=mempalace, tool=mempalace\_add\_drawer, inventory=none | definition text is untrusted self-report |
| `E-b80b0346ad` | definition | parsing | server=mempalace, tool=mempalace\_checkpoint, inventory=none | definition text is untrusted self-report |
| `E-14c4e38411` | definition | parsing | server=mempalace, tool=mempalace\_delete\_drawer, inventory=none | definition text is untrusted self-report |
| `E-c45adb9bcf` | definition | parsing | server=mempalace, tool=mempalace\_mine, inventory=none | definition text is untrusted self-report |
| `E-57dceb4f03` | definition | parsing | server=mempalace, tool=mempalace\_delete\_by\_source, inventory=none | definition text is untrusted self-report |
| `E-3ff1fa008a` | definition | parsing | server=mempalace, tool=mempalace\_sync, inventory=none | definition text is untrusted self-report |
| `E-d05812d233` | definition | parsing | server=mempalace, tool=mempalace\_get\_drawer, inventory=none | definition text is untrusted self-report |
| `E-18a68811e4` | definition | parsing | server=mempalace, tool=mempalace\_list\_drawers, inventory=none | definition text is untrusted self-report |
| `E-5a6eaba06a` | definition | parsing | server=mempalace, tool=mempalace\_update\_drawer, inventory=none | definition text is untrusted self-report |
| `E-5a80d747d6` | definition | parsing | server=mempalace, tool=mempalace\_diary\_write, inventory=none | definition text is untrusted self-report |
| `E-c35166e160` | definition | parsing | server=mempalace, tool=mempalace\_diary\_read, inventory=none | definition text is untrusted self-report |
| `E-16f7009675` | definition | parsing | server=mempalace, tool=mempalace\_hook\_settings, inventory=none | definition text is untrusted self-report |
| `E-e1b5527bf8` | definition | parsing | server=mempalace, tool=mempalace\_memories\_filed\_away, inventory=none | definition text is untrusted self-report |
| `E-5da0cee40c` | definition | parsing | server=mempalace, tool=mempalace\_reconnect, inventory=none | definition text is untrusted self-report |
| `E-fa4d7729bf` | definition | parsing | server=mempalace, tool=mempalace\_event\_append, inventory=none | definition text is untrusted self-report |
| `E-2a61a0edd3` | definition | parsing | server=mempalace, tool=mempalace\_task\_create, inventory=none | definition text is untrusted self-report |
| `E-324e1538a2` | definition | parsing | server=mempalace, tool=mempalace\_event\_list, inventory=none | definition text is untrusted self-report |
| `E-1f9f0a6029` | definition | parsing | server=mempalace, tool=mempalace\_event\_wait, inventory=none | definition text is untrusted self-report |
| `E-ce0e575b6b` | definition | parsing | server=mempalace, tool=mempalace\_event\_ack, inventory=none | definition text is untrusted self-report |
| `E-423d9c07ad` | definition | parsing | server=mempalace, tool=mempalace\_artifact\_put, inventory=none | definition text is untrusted self-report |
| `E-978d1a642f` | definition | parsing | server=mempalace, tool=mempalace\_artifact\_get, inventory=none | definition text is untrusted self-report |
| `E-a3ce9c8403` | definition | parsing | server=mempalace, tool=mempalace\_patch\_submit, inventory=none | definition text is untrusted self-report |

Версии правил, применённые в этом запуске:
- MEM-01 v2.0.0
- MEM-02 v2.0.0
- MEM-03 v2.0.0
- MEM-04 v2.0.0
- MEM-05 v2.0.0
- MEM-06 v2.0.0
- MEM-07 v2.0.0
- MEM-08 v2.0.0
- MEM-09 v2.0.0
- MEM-10 v2.0.0
- AUTH-01 v2.0.0
- AUTH-02 v2.0.0
- AUTH-03 v2.0.0
- AUTH-04 v2.0.0
- AUTH-05 v2.0.0
- AUTH-06 v2.0.0
- INFRA-01 v2.0.0
- INFRA-02 v2.0.0
- INFRA-03 v2.0.0
- TOOL-01 v2.0.0
- TOOL-02 v2.0.0
- TOOL-03 v2.0.0
- TOOL-04 v2.0.0
- TOOL-05 v2.0.0
- EGRESS-01 v2.0.0
- EGRESS-02 v2.0.0
- INV-01 v2.0.0
- INV-02 v2.0.0

*Аудит — диагностика, а не защита. Статические выводы описывают дефекты кода/конфигурации, а не наблюдаемое влияние на работающую модель. Недоверенные фрагменты экранированы; внешнее содержимое не подгружается.*
