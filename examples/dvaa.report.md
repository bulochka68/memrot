# Отчёт аудита безопасности агентной системы — dvaa

## 1. Цель, версии, среда, режим и пределы оценки

- Цель: **dvaa**, сборка: `faf3fb172ef526d12db0eb5377701549693118a6`, среда: локальный чекаут стенда в stand/ \(Damn Vulnerable AI Agent 0.9.3\)
- Режим: `offline`, профиль источников: `white_box`, run: `run-30ff0cf2afee`
- Версии: схема отчёта 2.0, движок 2.0.0, правила 2.0.0
- Runtime-проверки выполнялись: **нет**
- Состояние оценки: **partial**; вывод по безопасности: **findings\_present**
- ⚠ **Покрытие неполное**: не разрешённые контроли — MEM-08, MEM-09, AUTH-03, AUTH-06, INFRA-02, TOOL-01, TOOL-05, INV-01; недоступные адаптеры — нет
- Уверенность: medium — 0 finding\(s\) runtime-supported, 24 static-supported; static support shows a code/config defect, not an observed effect on the running model

## 2. Наиболее важные подтверждённые выводы и приоритеты

| Приоритет | Серьёзность | Правило | Finding | Статус подтверждения |
|---|---|---|---|---|
| P0 | CRITICAL | MEM-02 | User-session processing is linked to shared policy publication (`F-ee945c5cac`) | static_supported |
| P0 | CRITICAL | AUTH-01 | Input identity taken from an untrusted field (`F-43e8c36457`) | static_supported |
| P0 | CRITICAL | AUTH-01 | Input identity taken from an untrusted field (`F-9556db19ac`) | static_supported |
| P0 | CRITICAL | AUTH-02 | Resource authorization not enforced at mcp-tools (`F-632a5b297b`) | static_supported |
| P0 | CRITICAL | AUTH-02 | Resource authorization not enforced at mcp-tools (`F-feac28cfed`) | static_supported |
| P0 | CRITICAL | AUTH-02 | Resource authorization not enforced at a2a-bus (`F-783c4217cb`) | static_supported |
| P0 | CRITICAL | AUTH-02 | Resource authorization not enforced at mcp-tools (`F-4bebad75ac`) | static_supported |
| P0 | CRITICAL | AUTH-05 | Service credentials bypass end-user restrictions at a2a-bus (`F-5a12504ad8`) | static_supported |
| P0 | HIGH | MEM-01 | Personal memory read without audience binding (`F-e772e15517`) | static_supported |
| P0 | HIGH | MEM-01 | Personal memory read without audience binding (`F-29cec57136`) | static_supported |
| P0 | HIGH | MEM-03 | Memory owner / audience decided by an untrusted source (`F-c49e1900ec`) | static_supported |
| P0 | HIGH | MEM-04 | Memory content presented as rules without content authority (`F-aa77c5cf18`) | static_supported |
| P0 | HIGH | MEM-04 | Memory content presented as rules without content authority (`F-0e9f0f62be`) | static_supported |
| P0 | HIGH | MEM-06 | Shared publication without an approval transition (`F-3d77878e2f`) | static_supported |
| P0 | HIGH | INFRA-01 | agent-fleet holds rights on memoryStore:agent\_rule beyond policy (`F-4c279c92e9`) | static_supported |
| P0 | HIGH | TOOL-04 | Tool results can influence shared memory / policy (`F-b3388ee544`) | static_supported |
| P1 | HIGH | MEM-07 | Retrieval returns records before audience policy is applied (`F-e7cfabd900`) | static_supported |
| P1 | HIGH | MEM-07 | Retrieval returns records before audience policy is applied (`F-1b348a59f1`) | static_supported |
| P1 | HIGH | AUTH-04 | mcp-tools: token validation skips lookup, revocation, binding\_to\_principal (`F-d343cbf37b`) | static_supported |
| P1 | HIGH | EGRESS-01 | Uncontrolled transmission to web-fetch (`F-4325f98fc1`) | static_supported |

Гипотезы, требующие разбора: 6 (перечислены в разделе 5 отдельно от подтверждённых).

## 3. Покрытие, недоступные источники и незавершённые проверки

| Адаптер | Вид | Версия | Статус | Причины |
|---|---|---|---|---|
| mcp-config | mcp_inventory | 2.0.0 | **available** |  |
| source | source_snapshot | 2.0.0 | **available** |  |
| policy | policy_snapshot | 2.0.0 | **available** |  |
| deployment | deployment | 2.0.0 | **available** |  |

| Метрика | Значение | Знаменатель | Неизвестно | Ограничение |
|---|---|---|---|---|
| inventory_completeness | 5/5 \(100.0%\) | reference inventory \(profile/policy\) | 0 | the reference list may itself be partial |
| component_coverage | 6/11 \(54.5%\) | components of manifest/profile/inventory | 0 | does not show the depth of evaluation per component |
| mandatory_control_coverage | 18/26 \(69.2%\) | required controls minus justified not-applicable | 8 | INCONCLUSIVE, NOT\_EVALUATED and unknown applicability stay in the denominator |
| mandatory_control_coverage_static | 17/26 \(65.4%\) | same as above | 0 | static support shows code/config facts, not runtime behaviour |
| mandatory_control_coverage_runtime | 1/26 \(3.9%\) | same as above | 0 | runtime support is bound to the observed principal, build and environment |
| identity_coverage | 2/3 \(66.7%\) | expected access relations in policy | 0 | not replaced by the number of tokens used; a verified transition is a static fact |
| memory_stage_W | не определено | applicable memory cases | 0 | stages are never merged into one verified |
| memory_stage_R | не определено | applicable memory cases | 0 | stages are never merged into one verified |
| memory_stage_C | не определено | applicable memory cases | 0 | stages are never merged into one verified |
| memory_stage_B | не определено | applicable memory cases | 0 | stages are never merged into one verified |
| boundary_coverage | 2/4 \(50.0%\) | boundaries of the accepted model | 0 | an unreached backend is not counted as evaluated |
| execution_quality | не определено | control cases | 0 | errors are not excluded to make the report look complete |
| observation_quality | не определено | no trace | 0 | no runtime observation available |

Незавершённые контроли:
- `MEM-08`: NOT_EVALUATED — no revocation events; MEM-08 is a stage-D control \(roadmap: revocation fixtures\)
- `MEM-09`: NOT_EVALUATED — no background jobs declared; runtime job events are a stage-D source
- `AUTH-03`: NOT_EVALUATED — no security-mode flows or client-weakening attributes declared
- `AUTH-06`: NOT_EVALUATED — no revocation-check flows; stage D \(revocation traces on the roadmap\)
- `INFRA-02`: NOT_EVALUATED — no deployment snapshot with storage services
- `TOOL-01`: NOT_EVALUATED — required source\(s\) not bound: \['baseline'\]
- `TOOL-05`: INCONCLUSIVE — 2 text signal\(s\) recorded as hypotheses with fragment, rule and explanation; an imperative, Unicode or a link does not prove malicious intent - review required
- `INV-01`: INCONCLUSIVE — 

## 4. Карта компонентов и границ доверия

| Компонент | Тип | Роль | Источники инвентаря | Состояние знания |
|---|---|---|---|---|
| `server:toolbot` | mcp_server |  | configured, snapshot, summary | known |
| `server:databot` | mcp_server |  | configured, snapshot, summary | known |
| `server:pluginbot` | mcp_server |  | configured, snapshot, summary | known |
| `server:proxybot` | mcp_server |  | configured, snapshot, summary | known |
| `agent-fleet` | rest_service | user\_session\_handler | profile | assumed |
| `mcp-tools` | mcp_server | external\_tool\_host | profile | assumed |
| `a2a-bus` | orchestrator | delegation\_handler | profile | assumed |
| `agent-memory` | memory_store | memory\_store | profile | assumed |
| `dashboard` | rest_service | operator\_console | profile | assumed |
| `web-fetch` | external_provider | external\_provider | profile | assumed |
| `llm-provider` | external_provider | external\_provider | profile | assumed |

| Граница | Откуда → куда | Правило | Точка исполнения | Наблюдение |
|---|---|---|---|---|
| `B-client-mcp` | anonymous → mcp-tools | субъект аутентифицирован и авторизован на конкретный объект | mcp-tools | not_observed |
| `B-a2a` | a2a-bus → a2a-bus | идентичность отправителя подтверждена, делегирование ограничено задачей | a2a-bus | not_observed |
| `B-mem-publish` | agent-fleet → agent-memory | общие правила публикует только policy-admin после ревью | agent-memory | not_observed |
| `B-context` | agent-memory → agent-fleet | содержимое памяти включается в контекст как данные, а не как инструкции | agent-fleet | not_observed |

Рёбер графа: 15; состояния: identity\_binding:static\_path\_supported, identity\_binding:static\_path\_supported, memory\_write:static\_path\_supported, scope\_decision:static\_path\_supported, memory\_read:static\_path\_supported, context\_include:static\_path\_supported, publish:static\_path\_supported, context\_include:stat…

| Цепочка | Состояние | Условия |
|---|---|---|
| Результат инструмента → ответ агента → общая память агента \(правила\) | **static_path_supported** |  |
| Недоверенный веб-контент → агент → инструменты → исходящий канал | **static_path_supported** |  |

Индикатор LETHAL_TRIFECTA: **static\_path\_supported** — Code/configuration connect the three legs under the listed conditions \(static path\). A single tool holds all three legs: \['toolbot/read\_file', 'toolbot/write\_file', 'toolbot/fetch\_url'\].

### Инвентарь

| Сервер | Источник каталога | Handshake | Инструмент | Класс | Операции | Риск возможности | Основание |
|---|---|---|---|---|---|---|---|
| toolbot | snapshot | не выполнялся | `read\_file` | EXEC | EXECUTE,READ,CREATE,UPDATE,DELETE,TRANSMIT | CRITICAL | definition/assumed |
| toolbot | snapshot | не выполнялся | `write\_file` | EXEC | EXECUTE,READ,CREATE,UPDATE,DELETE,TRANSMIT | CRITICAL | definition/assumed |
| toolbot | snapshot | не выполнялся | `execute` | EXEC | EXECUTE,READ,CREATE,UPDATE,DELETE,TRANSMIT | CRITICAL | definition/assumed |
| toolbot | snapshot | не выполнялся | `fetch\_url` | EXEC | EXECUTE,READ,CREATE,UPDATE,DELETE,TRANSMIT | CRITICAL | definition/assumed |
| databot | snapshot | не выполнялся | `query\_database` | READ | READ | MEDIUM | definition/assumed |
| databot | snapshot | не выполнялся | `get\_user` | READ | READ | MEDIUM | definition/assumed |
| databot | snapshot | не выполнялся | `list\_tables` | READ | READ | MEDIUM | definition/assumed |
| pluginbot | snapshot | не выполнялся | `fetch\_data` | READ | READ,TRANSMIT | MEDIUM | definition/assumed |
| pluginbot | snapshot | не выполнялся | `store\_secret` | UNKNOWN | TRANSMIT | HIGH | definition/unknown |
| proxybot | snapshot | не выполнялся | `secure\_query` | READ | READ | MEDIUM | definition/assumed |
| proxybot | snapshot | не выполнялся | `sign\_document` | UNKNOWN | TRANSMIT | HIGH | definition/unknown |
| proxybot | snapshot | не выполнялся | `transfer\_funds` | UNKNOWN | TRANSMIT | HIGH | definition/unknown |

Расхождения инвентаря и контрактов:
- toolbot: 4 configured vs 1 policy\_authorized; 1 common; only in configured: \['execute', 'fetch\_url', 'write\_file'\]; only in policy\_authorized: -
  - 1/4 is the share of matching names between these two catalogues only - not a percentage of verified security and not a measurement of the running deployment
- toolbot: 4 live\_advertised vs 1 policy\_authorized; 1 common; only in live\_advertised: \['execute', 'fetch\_url', 'write\_file'\]; only in policy\_authorized: -
  - 1/4 is the share of matching names between these two catalogues only - not a percentage of verified security and not a measurement of the running deployment
- databot: 3 configured vs 2 policy\_authorized; 2 common; only in configured: \['query\_database'\]; only in policy\_authorized: -
  - 2/3 is the share of matching names between these two catalogues only - not a percentage of verified security and not a measurement of the running deployment
- databot: 3 live\_advertised vs 2 policy\_authorized; 2 common; only in live\_advertised: \['query\_database'\]; only in policy\_authorized: -
  - 2/3 is the share of matching names between these two catalogues only - not a percentage of verified security and not a measurement of the running deployment
- pluginbot: 2 configured vs 1 policy\_authorized; 1 common; only in configured: \['store\_secret'\]; only in policy\_authorized: -
  - 1/2 is the share of matching names between these two catalogues only - not a percentage of verified security and not a measurement of the running deployment
- pluginbot: 2 live\_advertised vs 1 policy\_authorized; 1 common; only in live\_advertised: \['store\_secret'\]; only in policy\_authorized: -
  - 1/2 is the share of matching names between these two catalogues only - not a percentage of verified security and not a measurement of the running deployment
- proxybot: 3 configured vs 1 policy\_authorized; 1 common; only in configured: \['sign\_document', 'transfer\_funds'\]; only in policy\_authorized: -
  - 1/3 is the share of matching names between these two catalogues only - not a percentage of verified security and not a measurement of the running deployment
- proxybot: 3 live\_advertised vs 1 policy\_authorized; 1 common; only in live\_advertised: \['sign\_document', 'transfer\_funds'\]; only in policy\_authorized: -
  - 1/3 is the share of matching names between these two catalogues only - not a percentage of verified security and not a measurement of the running deployment

## 5. Findings: основания и критерии закрытия

### 5.1 Подтверждённые (static_supported / runtime_supported)

- **[CRITICAL (подтверждено: static_supported)] MEM-02 `F-ee945c5cac` `USER_HANDLER_PUBLISHES_SHARED_POLICY`** — User-session processing is linked to shared policy publication
  - agent-fleet \(role user\_session\_handler\) contains a branch that publishes to agent-memory \(audience shared, authority policy\); trusted publishers: \['policy-admin'\].
  - Корневая причина: publication right is not separated from user-session processing
  - Наблюдаемый эффект: не наблюдался; возможный эффект: a user session can shape rules applied to all subjects
  - Основания: claims CL-MEM-02-F-mem-publish; evidence E-57fe45a571
  - Стадии памяти: W=not_evaluated, R=not_evaluated, C=not_evaluated, B=not_evaluated
  - Исправление: separate the shared-policy publisher; remove publication rights from the user handler at application and DB level Критерий закрытия: user processing holds no publication permission for shared policy; publisher has a distinct principal
  - Ограничения: DB rights of the running deployment not verified; passage of a concrete user text through the extraction step not verified
- **[CRITICAL (подтверждено: static_supported)] AUTH-01 `F-43e8c36457` `IDENTITY_FROM_UNTRUSTED_FIELD`** — Input identity taken from an untrusted field
  - a2a-bus establishes the principal from body\_field.
  - Наблюдаемый эффект: не наблюдался; возможный эффект: -
  - Основания: claims CL-AUTH-01-F-identity-a2a; evidence E-0e2b3e0a60
  - Исправление: derive the principal from authentication only; ignore body fields and conversation text Критерий закрытия: request body / conversation cannot override the authenticated principal \(fixture\)
- **[CRITICAL (подтверждено: static_supported)] AUTH-01 `F-9556db19ac` `IDENTITY_FROM_UNTRUSTED_FIELD`** — Input identity taken from an untrusted field
  - agent-fleet establishes the principal from anonymous.
  - Наблюдаемый эффект: не наблюдался; возможный эффект: -
  - Основания: claims CL-AUTH-01-F-identity-api; evidence E-0e2b3e0a60
  - Исправление: derive the principal from authentication only; ignore body fields and conversation text Критерий закрытия: request body / conversation cannot override the authenticated principal \(fixture\)
- **[CRITICAL (подтверждено: static_supported)] AUTH-02 `F-632a5b297b` `RESOURCE_AUTHORIZATION_MISSING`** — Resource authorization not enforced at mcp-tools
  - anonymous -\> mcp-tools -\> EXECUTE mcp tool \(read\_file / write\_file / execute / fetch\_url\): decision absent; conditions: none.
  - Наблюдаемый эффект: не наблюдался; возможный эффект: a valid token grants access to any object \(IDOR / BAC delegated to the model\)
  - Основания: claims CL-AUTH-02-T-mcp-tool-call; evidence E-0e2b3e0a60
  - Исправление: check subject -\> object permission at this hop, including client -\> account -\> operation relations Критерий закрытия: each receiving service decides authorization for the concrete object; foreign-object fixture is refused at this hop
  - Ограничения: an entry-API refusal does not cover a backend the request never reached
- **[CRITICAL (подтверждено: static_supported)] AUTH-02 `F-feac28cfed` `RESOURCE_AUTHORIZATION_MISSING`** — Resource authorization not enforced at mcp-tools
  - anonymous -\> mcp-tools -\> READ file\(path\): decision client\_controlled; conditions: none.
  - Наблюдаемый эффект: не наблюдался; возможный эффект: a valid token grants access to any object \(IDOR / BAC delegated to the model\)
  - Основания: claims CL-AUTH-02-T-file-read; evidence E-0e2b3e0a60
  - Исправление: check subject -\> object permission at this hop, including client -\> account -\> operation relations Критерий закрытия: each receiving service decides authorization for the concrete object; foreign-object fixture is refused at this hop
  - Ограничения: an entry-API refusal does not cover a backend the request never reached
- **[CRITICAL (подтверждено: static_supported)] AUTH-02 `F-783c4217cb` `RESOURCE_AUTHORIZATION_MISSING`** — Resource authorization not enforced at a2a-bus
  - end\_user -\> a2a-bus -\> EXECUTE делегированная задача: decision absent; conditions: none.
  - Наблюдаемый эффект: не наблюдался; возможный эффект: a valid token grants access to any object \(IDOR / BAC delegated to the model\)
  - Основания: claims CL-AUTH-02-T-a2a-delegate; evidence E-0e2b3e0a60
  - Исправление: check subject -\> object permission at this hop, including client -\> account -\> operation relations Критерий закрытия: each receiving service decides authorization for the concrete object; foreign-object fixture is refused at this hop
  - Ограничения: an entry-API refusal does not cover a backend the request never reached
- **[CRITICAL (подтверждено: static_supported)] AUTH-02 `F-4bebad75ac` `RESOURCE_AUTHORIZATION_MISSING`** — Resource authorization not enforced at mcp-tools
  - anonymous -\> mcp-tools -\> WRITE реестр инструментов: decision absent; conditions: none.
  - Наблюдаемый эффект: не наблюдался; возможный эффект: a valid token grants access to any object \(IDOR / BAC delegated to the model\)
  - Основания: claims CL-AUTH-02-T-plugin-register; evidence E-0e2b3e0a60
  - Исправление: check subject -\> object permission at this hop, including client -\> account -\> operation relations Критерий закрытия: each receiving service decides authorization for the concrete object; foreign-object fixture is refused at this hop
  - Ограничения: an entry-API refusal does not cover a backend the request never reached
- **[CRITICAL (подтверждено: static_supported)] AUTH-05 `F-5a12504ad8` `UNBOUNDED_DELEGATION`** — Service credentials bypass end-user restrictions at a2a-bus
  - a2a-bus calls делегированная задача with passthrough\_unbound; conditions: none.
  - Наблюдаемый эффект: не наблюдался; возможный эффект: -
  - Основания: claims CL-AUTH-05-T-a2a-delegate; evidence E-0e2b3e0a60
  - Исправление: delegate with subject-bound tokens \(token exchange / on-behalf-of\) scoped to the task and resource Критерий закрытия: downstream calls carry the end-user binding; a service token alone is refused for user resources
- **[HIGH (подтверждено: static_supported)] MEM-01 `F-e772e15517` `MEMORY_ISOLATION_MISSING`** — Personal memory read without audience binding
  - agent-memory reads memory type 'session\_memory' \(audience user\) without binding the query to the requesting subject.
  - Наблюдаемый эффект: не наблюдался; возможный эффект: cross-subject memory disclosure
  - Основания: claims CL-MEM-01-F-mem-read; evidence E-0e2b3e0a60
  - Исправление: bind every retrieval to the authenticated subject / allowed audience Критерий закрытия: retrieval paths for personal types carry an audience filter; fixture read for another subject returns nothing
  - Ограничения: scope/tenant fields in a document do not prove access control enforcement
- **[HIGH (подтверждено: static_supported)] MEM-01 `F-29cec57136` `MEMORY_ISOLATION_MISSING`** — Personal memory read without audience binding
  - agent-memory reads memory type 'preloaded\_secret' \(audience user\) without binding the query to the requesting subject.
  - Наблюдаемый эффект: не наблюдался; возможный эффект: cross-subject memory disclosure
  - Основания: claims CL-MEM-01-F-mem-secret-read; evidence E-0e2b3e0a60
  - Исправление: bind every retrieval to the authenticated subject / allowed audience Критерий закрытия: retrieval paths for personal types carry an audience filter; fixture read for another subject returns nothing
  - Ограничения: scope/tenant fields in a document do not prove access control enforcement
- **[HIGH (подтверждено: static_supported)] MEM-03 `F-c49e1900ec` `SCOPE_DECIDED_BY_UNTRUSTED_SOURCE`** — Memory owner / audience decided by an untrusted source
  - agent-fleet takes the audience of 'session\_memory' from message\_content; validation: none.
  - Наблюдаемый эффект: не наблюдался; возможный эффект: metadata produced by a model or external content sets write authority
  - Основания: claims CL-MEM-03-F-mem-scope; evidence E-0e2b3e0a60
  - Исправление: resolve owner and audience server-side from the authenticated principal and policy Критерий закрытия: proposed scope from model/external content is advisory only; the server decides
- **[HIGH (подтверждено: static_supported)] MEM-04 `F-aa77c5cf18` `MEMORY_PRESENTED_AS_RULES`** — Memory content presented as rules without content authority
  - agent-memory includes 'agent\_rule' in the system role as rules; policy authority for the type: policy, publisher trusted: False.
  - Наблюдаемый эффект: не наблюдался; возможный эффект: reference data or user-derived text gains instruction authority
  - Основания: claims CL-MEM-04-F-mem-context; evidence E-57fe45a571
  - Стадии памяти: W=not_evaluated, R=not_evaluated, C=not_evaluated, B=not_evaluated
  - Исправление: mark memory blocks by authority; only trusted-publisher records may be presented as rules Критерий закрытия: context assembly separates data blocks from instruction blocks and records the authority of each
- **[HIGH (подтверждено: static_supported)] MEM-04 `F-0e9f0f62be` `MEMORY_PRESENTED_AS_RULES`** — Memory content presented as rules without content authority
  - mcp-tools includes 'agent\_rule' in the system role as rules; policy authority for the type: policy, publisher trusted: False.
  - Наблюдаемый эффект: не наблюдался; возможный эффект: reference data or user-derived text gains instruction authority
  - Основания: claims CL-MEM-04-F-tool-result-authority; evidence E-0e2b3e0a60
  - Стадии памяти: W=not_evaluated, R=not_evaluated, C=not_evaluated, B=not_evaluated
  - Исправление: mark memory blocks by authority; only trusted-publisher records may be presented as rules Критерий закрытия: context assembly separates data blocks from instruction blocks and records the authority of each
- **[HIGH (подтверждено: static_supported)] MEM-06 `F-3d77878e2f` `AUTOMATIC_TRUST_ELEVATION`** — Shared publication without an approval transition
  - agent-fleet: Обработчик пользовательской сессии сам публикует записи авторитета policy; отдельного издателя и ревью нет \(mechanism: публикация без отдельного издателя и без ревью; review required by policy: True\).
  - Наблюдаемый эффект: не наблюдался; возможный эффект: a paraphrase by the assistant or a high model confidence value becomes shared truth
  - Основания: claims CL-MEM-06-F-mem-publish; evidence E-57fe45a571
  - Исправление: require an authorized review/approval transition before shared publication; ignore self-reported confidence for authority Критерий закрытия: shared records carry review\_state=approved with an approval\_ref from a trusted publisher
- **[HIGH (подтверждено: static_supported)] INFRA-01 `F-4c279c92e9` `EXCESSIVE_STORE_RIGHTS`** — agent-fleet holds rights on memoryStore:agent\_rule beyond policy
  - observed \['publish', 'read', 'write'\], policy allows \['read'\].
  - Наблюдаемый эффект: не наблюдался; возможный эффект: -
  - Основания: claims CL-INFRA-01-F-store-access-memory; evidence E-0e2b3e0a60
  - Исправление: grant per-service store credentials with least privilege; keep shared-policy publication on a separate principal Критерий закрытия: service rights on memory stores match policy; publication is a separate credential
- **[HIGH (подтверждено: static_supported)] TOOL-04 `F-b3388ee544` `TOOL_RESULT_REACHES_POLICY`** — Tool results can influence shared memory / policy
  - chain \['mcp-tools', 'agent-fleet', 'agent-memory'\] is static\_path\_supported; conditions: none.
  - Наблюдаемый эффект: не наблюдался; возможный эффект: content returned by a tool is transformed and published as shared rules
  - Основания: claims CL-TOOL-04-tool-result-to-shared-memory; evidence E-0e2b3e0a60
  - Исправление: keep tool results as data through derivation; publication of policy needs a separate authorized process Критерий закрытия: no derivation path from tool results to shared policy without an authorized review
- **[HIGH (подтверждено: static_supported)] MEM-07 `F-e7cfabd900` `RETRIEVAL_WITHOUT_AUDIENCE_FILTER`** — Retrieval returns records before audience policy is applied
  - agent-memory: Recall отдаёт все записи агента любому вызывающему: фильтра по субъекту нет \(cross-session persistence\).
  - Наблюдаемый эффект: не наблюдался; возможный эффект: -
  - Основания: claims CL-MEM-07-F-mem-read; evidence E-0e2b3e0a60
  - Исправление: apply audience filtering in the query / index partition, before ranking and context assembly Критерий закрытия: retrieval, cache keys and index partitions include the audience; fixture retrieval for a foreign audience is empty
- **[HIGH (подтверждено: static_supported)] MEM-07 `F-1b348a59f1` `RETRIEVAL_WITHOUT_AUDIENCE_FILTER`** — Retrieval returns records before audience policy is applied
  - agent-memory: Преднастроенные секреты агента выдаются по запросу без какой-либо проверки вызывающего.
  - Наблюдаемый эффект: не наблюдался; возможный эффект: -
  - Основания: claims CL-MEM-07-F-mem-secret-read; evidence E-0e2b3e0a60
  - Исправление: apply audience filtering in the query / index partition, before ranking and context assembly Критерий закрытия: retrieval, cache keys and index partitions include the audience; fixture retrieval for a foreign audience is empty
- **[HIGH (подтверждено: static_supported)] AUTH-04 `F-d343cbf37b` `TOKEN_VALIDATION_INCOMPLETE`** — mcp-tools: token validation skips lookup, revocation, binding\_to\_principal
  - scheme api\_key requires \['lookup', 'revocation', 'binding\_to\_principal'\]; observed \{'lookup': False, 'revocation': False, 'binding\_to\_principal': False\}.
  - Наблюдаемый эффект: не наблюдался; возможный эффект: a token issued for another audience/issuer is accepted by this service
  - Основания: claims CL-AUTH-04-mcp-tools; evidence E-0e2b3e0a60
  - Исправление: validate issuer, audience, signature, expiry and algorithm against trusted config of this service Критерий закрытия: each receiving service rejects tokens with a foreign issuer/audience \(fixture\)
- **[HIGH (подтверждено: static_supported)] EGRESS-01 `F-4325f98fc1` `EGRESS_DATA_CATEGORY_UNCONTROLLED`** — Uncontrolled transmission to web-fetch
  - destination web-fetch is not an allowed destination.
  - Наблюдаемый эффект: не наблюдался; возможный эффект: client identifiers or portfolio data reach an external provider inside a query
  - Основания: claims CL-EGRESS-01-F-egress-fetch; evidence E-0e2b3e0a60
  - Исправление: control both destination and data category; filter model-composed queries before transmission Критерий закрытия: egress policy is enforced for destination and category; fixture observes the actual payload locally
- **[HIGH (подтверждено: static_supported)] EGRESS-01 `F-26c293e118` `EGRESS_DATA_CATEGORY_UNCONTROLLED`** — Uncontrolled transmission to web-fetch
  - destination web-fetch is not an allowed destination.
  - Наблюдаемый эффект: не наблюдался; возможный эффект: client identifiers or portfolio data reach an external provider inside a query
  - Основания: claims CL-EGRESS-01-F-egress-webfetch; evidence E-c243dd7167
  - Исправление: control both destination and data category; filter model-composed queries before transmission Критерий закрытия: egress policy is enforced for destination and category; fixture observes the actual payload locally
- **[MEDIUM (подтверждено: static_supported)] MEM-05 `F-d3aafeef03` `PROVENANCE_LOST`** — Derived memory loses its parents
  - agent-fleet -\> agent-memory: Запись в память идёт из текста пользовательского сообщения без владельца, сессии и ссылки на источник; kept fields: none.
  - Наблюдаемый эффект: не наблюдался; возможный эффект: tool results and untrusted fragments cannot be traced into derived memory; revocation cannot reach derivatives
  - Основания: claims CL-MEM-05-F-mem-write; evidence E-0e2b3e0a60
  - Исправление: link derived records to all parent events and transformation versions; make lost lineage visible Критерий закрытия: every derived record carries source\_event\_refs / derived\_from or an explicit lineage\_completeness=lost
- **[MEDIUM (подтверждено: static_supported)] MEM-10 `F-aa95aa591e` `RETENTION_UNDEFINED_OR_EXCEEDED`** — Retention for memory type session\_memory is undefined or exceeds policy
  - policy expects ttl\<=86400s; observed ttl=None \(mechanism none\).
  - Наблюдаемый эффект: не наблюдался; возможный эффект: -
  - Основания: claims CL-MEM-10-session\_memory; evidence E-0e2b3e0a60
  - Исправление: define TTL, volume limits, refresh and cleanup per memory type; prevent uncontrolled restoration Критерий закрытия: each memory type has a retention policy in config and a cleanup mechanism with maintenance events
  - Ограничения: stage D: maintenance events are on the roadmap
- **[MEDIUM (подтверждено: static_supported)] MEM-10 `F-5628acaecc` `RETENTION_UNDEFINED_OR_EXCEEDED`** — Retention for memory type agent\_rule is undefined or exceeds policy
  - policy expects ttl\<=7776000s; observed ttl=None \(mechanism none\).
  - Наблюдаемый эффект: не наблюдался; возможный эффект: -
  - Основания: claims CL-MEM-10-agent\_rule; evidence E-0e2b3e0a60
  - Исправление: define TTL, volume limits, refresh and cleanup per memory type; prevent uncontrolled restoration Критерий закрытия: each memory type has a retention policy in config and a cleanup mechanism with maintenance events
  - Ограничения: stage D: maintenance events are on the roadmap

### 5.2 Гипотезы и сигналы (требуют разбора; не являются подтверждённым нарушением)

- **[потенциально HIGH (гипотеза: hypothesis)] TOOL-05 `F-5773d1c20e` `UNCONSTRAINED_EXEC_PARAMETER`** (toolbot/execute) — Unconstrained execution parameter
  - execute.command is a free string with no enum/pattern - arbitrary execution surface
  - Ограничения: schema heuristic: a hypothesis about misuse potential, not an observed abuse
- **[потенциально HIGH (гипотеза: hypothesis)] TOOL-05 `F-47a3a7dedf` `UNCONSTRAINED_EXEC_PARAMETER`** (databot/query\_database) — Unconstrained execution parameter
  - query\_database.query is a free string with no enum/pattern - arbitrary execution surface
  - Ограничения: schema heuristic: a hypothesis about misuse potential, not an observed abuse
- **[потенциально MEDIUM (гипотеза: hypothesis)] INV-01 `F-6775e741ba` `INVENTORY_MISMATCH`** (toolbot) — Inventory mismatch for toolbot \(configured/policy\_authorized\)
  - toolbot: 4 configured vs 1 policy\_authorized; 1 common; only in configured: \['execute', 'fetch\_url', 'write\_file'\]; only in policy\_authorized: -; unexplained: \['execute', 'fetch\_url', 'write\_file'\].
  - Ограничения: a mismatch is not automatically a hidden tool; reasons may be legitimate
- **[потенциально MEDIUM (гипотеза: hypothesis)] INV-01 `F-7329ea734d` `INVENTORY_MISMATCH`** (databot) — Inventory mismatch for databot \(configured/policy\_authorized\)
  - databot: 3 configured vs 2 policy\_authorized; 2 common; only in configured: \['query\_database'\]; only in policy\_authorized: -; unexplained: \['query\_database'\].
  - Ограничения: a mismatch is not automatically a hidden tool; reasons may be legitimate
- **[потенциально MEDIUM (гипотеза: hypothesis)] INV-01 `F-114de8b395` `INVENTORY_MISMATCH`** (pluginbot) — Inventory mismatch for pluginbot \(configured/policy\_authorized\)
  - pluginbot: 2 configured vs 1 policy\_authorized; 1 common; only in configured: \['store\_secret'\]; only in policy\_authorized: -; unexplained: \['store\_secret'\].
  - Ограничения: a mismatch is not automatically a hidden tool; reasons may be legitimate
- **[потенциально MEDIUM (гипотеза: hypothesis)] INV-01 `F-8d66b62c3a` `INVENTORY_MISMATCH`** (proxybot) — Inventory mismatch for proxybot \(configured/policy\_authorized\)
  - proxybot: 3 configured vs 1 policy\_authorized; 1 common; only in configured: \['sign\_document', 'transfer\_funds'\]; only in policy\_authorized: -; unexplained: \['sign\_document', 'transfer\_funds'\].
  - Ограничения: a mismatch is not automatically a hidden tool; reasons may be legitimate

## 6. Результаты памяти по стадиям W/R/C/B

Стадийные наблюдения памяти не проводились (нет случаев/трасс): W/R/C/B = not_evaluated.

| Правило | Применимость | Выполнение | Исход | Интерпретация |
|---|---|---|---|---|
| MEM-01 | applicable | completed | **FAIL** |  |
| MEM-02 | applicable | completed | **FAIL** |  |
| MEM-03 | applicable | completed | **FAIL** |  |
| MEM-04 | applicable | completed | **FAIL** |  |
| MEM-05 | applicable | completed | **FAIL** |  |
| MEM-06 | applicable | completed | **FAIL** |  |
| MEM-07 | applicable | completed | **FAIL** |  |
| MEM-08 | applicable | skipped | **NOT_EVALUATED** | no revocation events; MEM-08 is a stage-D control \(roadmap: revocation fixtures\) |
| MEM-09 | applicable | skipped | **NOT_EVALUATED** | no background jobs declared; runtime job events are a stage-D source |
| MEM-10 | applicable | completed | **FAIL** |  |

## 7. Результаты авторизации и исходящих эффектов

| Правило | Применимость | Выполнение | Исход | Границы | Интерпретация |
|---|---|---|---|---|---|
| AUTH-01 | applicable | completed | **FAIL** |  |  |
| AUTH-02 | applicable | completed | **FAIL** | B-a2a, B-client-mcp | each hop evaluated separately; a refusal at one hop does not cover the next |
| AUTH-03 | applicable | skipped | **NOT_EVALUATED** |  | no security-mode flows or client-weakening attributes declared |
| AUTH-04 | applicable | completed | **FAIL** |  |  |
| AUTH-05 | applicable | completed | **FAIL** |  |  |
| AUTH-06 | applicable | skipped | **NOT_EVALUATED** |  | no revocation-check flows; stage D \(revocation traces on the roadmap\) |
| INFRA-01 | applicable | completed | **FAIL** |  |  |
| INFRA-02 | applicable | skipped | **NOT_EVALUATED** |  | no deployment snapshot with storage services |
| INFRA-03 | not_applicable | skipped | **NOT_APPLICABLE** |  | no controlled validation in this mode |
| TOOL-01 | applicable | skipped | **NOT_EVALUATED** |  | required source\(s\) not bound: \['baseline'\] |
| TOOL-02 | applicable | completed | **PASS** |  | 12 consistent, 0 mismatched contract\(s\) |
| TOOL-03 | applicable | completed | **PASS** |  | router namespace: flat; 0 name collision\(s\) |
| TOOL-04 | applicable | completed | **FAIL** |  |  |
| TOOL-05 | applicable | completed | **INCONCLUSIVE** |  | 2 text signal\(s\) recorded as hypotheses with fragment, rule and explanation; an imperative, Unicode or a link does not prove malicious intent - review required |
| EGRESS-01 | applicable | completed | **FAIL** |  |  |
| EGRESS-02 | not_applicable | skipped | **NOT_APPLICABLE** |  | no controlled validation in this mode |
| INV-01 | applicable | completed | **INCONCLUSIVE** |  |  |
| INV-02 | applicable | completed | **PASS** |  |  |

## 8. Изменения относительно совместимого baseline

Baseline не задан; сравнение не выполнялось.

## 9. План исправлений, повторная оценка и ограничения

| Приоритет | Finding | Исправление | Критерий закрытия |
|---|---|---|---|
| P0 | `F-ee945c5cac` | separate the shared-policy publisher; remove publication rights from the user handler at application and DB level | user processing holds no publication permission for shared policy; publisher has a distinct principal |
| P0 | `F-43e8c36457` | derive the principal from authentication only; ignore body fields and conversation text | request body / conversation cannot override the authenticated principal \(fixture\) |
| P0 | `F-9556db19ac` | derive the principal from authentication only; ignore body fields and conversation text | request body / conversation cannot override the authenticated principal \(fixture\) |
| P0 | `F-632a5b297b` | check subject -\> object permission at this hop, including client -\> account -\> operation relations | each receiving service decides authorization for the concrete object; foreign-object fixture is refused at this hop |
| P0 | `F-feac28cfed` | check subject -\> object permission at this hop, including client -\> account -\> operation relations | each receiving service decides authorization for the concrete object; foreign-object fixture is refused at this hop |
| P0 | `F-783c4217cb` | check subject -\> object permission at this hop, including client -\> account -\> operation relations | each receiving service decides authorization for the concrete object; foreign-object fixture is refused at this hop |
| P0 | `F-4bebad75ac` | check subject -\> object permission at this hop, including client -\> account -\> operation relations | each receiving service decides authorization for the concrete object; foreign-object fixture is refused at this hop |
| P0 | `F-5a12504ad8` | delegate with subject-bound tokens \(token exchange / on-behalf-of\) scoped to the task and resource | downstream calls carry the end-user binding; a service token alone is refused for user resources |
| P0 | `F-e772e15517` | bind every retrieval to the authenticated subject / allowed audience | retrieval paths for personal types carry an audience filter; fixture read for another subject returns nothing |
| P0 | `F-29cec57136` | bind every retrieval to the authenticated subject / allowed audience | retrieval paths for personal types carry an audience filter; fixture read for another subject returns nothing |
| P0 | `F-c49e1900ec` | resolve owner and audience server-side from the authenticated principal and policy | proposed scope from model/external content is advisory only; the server decides |
| P0 | `F-aa77c5cf18` | mark memory blocks by authority; only trusted-publisher records may be presented as rules | context assembly separates data blocks from instruction blocks and records the authority of each |
| P0 | `F-0e9f0f62be` | mark memory blocks by authority; only trusted-publisher records may be presented as rules | context assembly separates data blocks from instruction blocks and records the authority of each |
| P0 | `F-3d77878e2f` | require an authorized review/approval transition before shared publication; ignore self-reported confidence for authority | shared records carry review\_state=approved with an approval\_ref from a trusted publisher |
| P0 | `F-4c279c92e9` | grant per-service store credentials with least privilege; keep shared-policy publication on a separate principal | service rights on memory stores match policy; publication is a separate credential |
| P0 | `F-b3388ee544` | keep tool results as data through derivation; publication of policy needs a separate authorized process | no derivation path from tool results to shared policy without an authorized review |
| P1 | `F-e7cfabd900` | apply audience filtering in the query / index partition, before ranking and context assembly | retrieval, cache keys and index partitions include the audience; fixture retrieval for a foreign audience is empty |
| P1 | `F-1b348a59f1` | apply audience filtering in the query / index partition, before ranking and context assembly | retrieval, cache keys and index partitions include the audience; fixture retrieval for a foreign audience is empty |
| P1 | `F-d343cbf37b` | validate issuer, audience, signature, expiry and algorithm against trusted config of this service | each receiving service rejects tokens with a foreign issuer/audience \(fixture\) |
| P1 | `F-4325f98fc1` | control both destination and data category; filter model-composed queries before transmission | egress policy is enforced for destination and category; fixture observes the actual payload locally |
| P1 | `F-26c293e118` | control both destination and data category; filter model-composed queries before transmission | egress policy is enforced for destination and category; fixture observes the actual payload locally |
| P1 | `F-d3aafeef03` | link derived records to all parent events and transformation versions; make lost lineage visible | every derived record carries source\_event\_refs / derived\_from or an explicit lineage\_completeness=lost |
| P2 | `F-aa95aa591e` | define TTL, volume limits, refresh and cleanup per memory type; prevent uncontrolled restoration | each memory type has a retention policy in config and a cleanup mechanism with maintenance events |
| P2 | `F-5628acaecc` | define TTL, volume limits, refresh and cleanup per memory type; prevent uncontrolled restoration | each memory type has a retention policy in config and a cleanup mechanism with maintenance events |

Ограничения оценки:
- MEM-08: NOT\_EVALUATED \(no revocation events; MEM-08 is a stage-D control \(roadmap: revocation fixtures\)\)
- MEM-09: NOT\_EVALUATED \(no background jobs declared; runtime job events are a stage-D source\)
- AUTH-03: NOT\_EVALUATED \(no security-mode flows or client-weakening attributes declared\)
- AUTH-06: NOT\_EVALUATED \(no revocation-check flows; stage D \(revocation traces on the roadmap\)\)
- INFRA-02: NOT\_EVALUATED \(no deployment snapshot with storage services\)
- TOOL-01: NOT\_EVALUATED \(required source\(s\) not bound: \['baseline'\]\)
- TOOL-05: INCONCLUSIVE \(2 text signal\(s\) recorded as hypotheses with fragment, rule and explanation; an imperative, Unicode or a link does not prove malicious intent - review required\)
- INV-01: INCONCLUSIVE \(\)
- no runtime validation was performed: all supported claims are static \(config, definitions, source, policy\)

## 10. Реестр свидетельств и версий правил

Свидетельств: 26; утверждений: 49; правила: 2.0.0

| ID | Источник | Метод | Локатор | Ограничения |
|---|---|---|---|---|
| `E-2756ba723b` | config | parsing | path=examples/dvaa.config.json, kind=mcp\_config |  |
| `E-6cd330d91b` | definition | parsing | path=examples/dvaa.config.json, server=toolbot, inventory=configured | configured catalogue: what the client config lists, not what a server advertises |
| `E-27634d3af8` | definition | parsing | path=examples/dvaa.tools.snapshot.json, server=toolbot, inventory=snapshot | snapshot of an earlier handshake; identity/time recorded if the snapshot carried them |
| `E-0e2d0fd3d7` | definition | parsing | path=examples/dvaa.config.json, server=databot, inventory=configured | configured catalogue: what the client config lists, not what a server advertises |
| `E-9dcf221164` | definition | parsing | path=examples/dvaa.tools.snapshot.json, server=databot, inventory=snapshot | snapshot of an earlier handshake; identity/time recorded if the snapshot carried them |
| `E-a25cd61327` | definition | parsing | path=examples/dvaa.config.json, server=pluginbot, inventory=configured | configured catalogue: what the client config lists, not what a server advertises |
| `E-e77e136c8a` | definition | parsing | path=examples/dvaa.tools.snapshot.json, server=pluginbot, inventory=snapshot | snapshot of an earlier handshake; identity/time recorded if the snapshot carried them |
| `E-664672717f` | definition | parsing | path=examples/dvaa.config.json, server=proxybot, inventory=configured | configured catalogue: what the client config lists, not what a server advertises |
| `E-32e2f6d600` | definition | parsing | path=examples/dvaa.tools.snapshot.json, server=proxybot, inventory=snapshot | snapshot of an earlier handshake; identity/time recorded if the snapshot carried them |
| `E-0e2b3e0a60` | source_code | static_analysis | path=src/index.js, lines=\[1, 2231\] |  |
| `E-57fe45a571` | source_code | static_analysis | path=src/core/agents.js, lines=\[1, 851\] |  |
| `E-c243dd7167` | source_code | static_analysis | path=src/web-fetch.js, lines=\[1, 318\] |  |
| `E-0956f93534` | policy_snapshot | policy_inspection | path=examples/dvaa.policy.json, policy\_id=dvaa-expected, version=1.0.0 | declared expectations; not evidence of enforcement |
| `E-01eb06817f` | deployment_snapshot | parsing | path=stand/docker-compose.yml, service=dvaa | bind/publication only; reachability per network zone not established |
| `E-533f3dea11` | definition | parsing | server=toolbot, tool=read\_file, inventory=snapshot | definition text is untrusted self-report |
| `E-91e165ffb9` | definition | parsing | server=toolbot, tool=write\_file, inventory=snapshot | definition text is untrusted self-report |
| `E-141f7f0693` | definition | parsing | server=toolbot, tool=execute, inventory=snapshot | definition text is untrusted self-report |
| `E-db962e0317` | definition | parsing | server=toolbot, tool=fetch\_url, inventory=snapshot | definition text is untrusted self-report |
| `E-ae30a21bf2` | definition | parsing | server=databot, tool=query\_database, inventory=snapshot | definition text is untrusted self-report |
| `E-58db535b9a` | definition | parsing | server=databot, tool=get\_user, inventory=snapshot | definition text is untrusted self-report |
| `E-73a5321628` | definition | parsing | server=databot, tool=list\_tables, inventory=snapshot | definition text is untrusted self-report |
| `E-1ca08768b1` | definition | parsing | server=pluginbot, tool=fetch\_data, inventory=snapshot | definition text is untrusted self-report |
| `E-08116b9c83` | definition | parsing | server=pluginbot, tool=store\_secret, inventory=snapshot | definition text is untrusted self-report |
| `E-b17e811b2d` | definition | parsing | server=proxybot, tool=secure\_query, inventory=snapshot | definition text is untrusted self-report |
| `E-30eca2ddc0` | definition | parsing | server=proxybot, tool=sign\_document, inventory=snapshot | definition text is untrusted self-report |
| `E-531a61b0bb` | definition | parsing | server=proxybot, tool=transfer\_funds, inventory=snapshot | definition text is untrusted self-report |

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
