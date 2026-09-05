# Отчёт аудита безопасности агентной системы — genai-invest-stand

## 1. Цель, версии, среда, режим и пределы оценки

- Цель: **genai-invest-stand**, сборка: `912edfb1a3891f07a6986b15ca8b6f9188800709`, среда: local-compose-stand \(branch bulochka68-with-stand\)
- Режим: `offline`, профиль источников: `white_box`, run: `run-18d18234f15c`
- Версии: схема отчёта 2.0, движок 2.0.0, правила 2.0.0
- Runtime-проверки выполнялись: **нет**
- Состояние оценки: **partial**; вывод по безопасности: **findings\_present**
- ⚠ **Покрытие неполное**: не разрешённые контроли — MEM-08, TOOL-01, TOOL-05, INV-01, INV-02; недоступные адаптеры — нет
- Уверенность: medium — 0 finding\(s\) runtime-supported, 26 static-supported; static support shows a code/config defect, not an observed effect on the running model

## 2. Наиболее важные подтверждённые выводы и приоритеты

| Приоритет | Серьёзность | Правило | Finding | Статус подтверждения |
|---|---|---|---|---|
| P0 | CRITICAL | MEM-02 | User-session processing is linked to shared policy publication (`F-ef5eae79b2`) | static_supported |
| P0 | CRITICAL | AUTH-02 | Resource authorization not enforced at mcp-invest (`F-3d561de31c`) | static_supported |
| P0 | CRITICAL | AUTH-02 | Resource authorization not enforced at invest-server (`F-974158ed15`) | static_supported |
| P0 | CRITICAL | AUTH-02 | Resource authorization not enforced at invest-server (`F-c3ac7ea94b`) | static_supported |
| P0 | CRITICAL | AUTH-03 | Client parameters weaken mandatory server checks at agent-api (`F-96ac946f83`) | static_supported |
| P0 | CRITICAL | AUTH-03 | Client parameters weaken mandatory server checks at mcp-invest (`F-cc44e3d173`) | static_supported |
| P0 | CRITICAL | AUTH-03 | Client parameters weaken mandatory server checks at invest-server (`F-485f6ad0df`) | static_supported |
| P0 | CRITICAL | AUTH-05 | Service credentials bypass end-user restrictions at agent (`F-c9b97e6334`) | static_supported |
| P0 | HIGH | MEM-03 | Memory owner / audience decided by an untrusted source (`F-eb603c8b4a`) | static_supported |
| P0 | HIGH | MEM-04 | Memory content presented as rules without content authority (`F-066fafcc1b`) | static_supported |
| P0 | HIGH | MEM-06 | Retelling or model confidence acts as publication permission (`F-2a34099aa7`) | static_supported |
| P0 | HIGH | MEM-06 | Shared publication without an approval transition (`F-864c303962`) | static_supported |
| P0 | HIGH | INFRA-01 | agent-api holds rights on mongo:agent\_policy\_memories beyond policy (`F-d4c5f187ec`) | static_supported |
| P0 | HIGH | INFRA-02 | redis storage port published on the host (`F-4cfa945006`) | static_supported |
| P0 | HIGH | INFRA-02 | mongo storage port published on the host (`F-a23c2cf23d`) | static_supported |
| P0 | HIGH | TOOL-04 | Tool results can influence shared memory / policy (`F-be38f8e6b7`) | static_supported |
| P1 | HIGH | AUTH-04 | mcp-invest: token validation skips audience (`F-95ab9aadae`) | static_supported |
| P1 | HIGH | AUTH-04 | invest-server: token validation skips audience (`F-b10c949fb6`) | static_supported |
| P1 | HIGH | AUTH-04 | agent-api: token validation skips issuer, audience (`F-16e42e7d4e`) | static_supported |
| P1 | HIGH | EGRESS-01 | Uncontrolled transmission to duckduckgo (`F-c2c7b528ad`) | static_supported |

Гипотезы, требующие разбора: 4 (перечислены в разделе 5 отдельно от подтверждённых).

## 3. Покрытие, недоступные источники и незавершённые проверки

| Адаптер | Вид | Версия | Статус | Причины |
|---|---|---|---|---|
| mcp-config | mcp_inventory | 2.0.0 | **available** |  |
| source | source_snapshot | 2.0.0 | **available** |  |
| policy | policy_snapshot | 2.0.0 | **available** |  |
| deployment | deployment | 2.0.0 | **available** |  |

| Метрика | Значение | Знаменатель | Неизвестно | Ограничение |
|---|---|---|---|---|
| inventory_completeness | 10/15 \(66.7%\) | reference inventory \(profile/policy\) | 0 | the reference list may itself be partial |
| component_coverage | 9/16 \(56.2%\) | components of manifest/profile/inventory | 0 | does not show the depth of evaluation per component |
| mandatory_control_coverage | 21/26 \(80.8%\) | required controls minus justified not-applicable | 5 | INCONCLUSIVE, NOT\_EVALUATED and unknown applicability stay in the denominator |
| mandatory_control_coverage_static | 21/26 \(80.8%\) | same as above | 0 | static support shows code/config facts, not runtime behaviour |
| mandatory_control_coverage_runtime | 0/26 \(0.0%\) | same as above | 0 | runtime support is bound to the observed principal, build and environment |
| identity_coverage | 2/4 \(50.0%\) | expected access relations in policy | 0 | not replaced by the number of tokens used; a verified transition is a static fact |
| memory_stage_W | не определено | applicable memory cases | 0 | stages are never merged into one verified |
| memory_stage_R | не определено | applicable memory cases | 0 | stages are never merged into one verified |
| memory_stage_C | не определено | applicable memory cases | 0 | stages are never merged into one verified |
| memory_stage_B | не определено | applicable memory cases | 0 | stages are never merged into one verified |
| boundary_coverage | 3/5 \(60.0%\) | boundaries of the accepted model | 0 | an unreached backend is not counted as evaluated |
| execution_quality | не определено | control cases | 0 | errors are not excluded to make the report look complete |
| observation_quality | не определено | no trace | 0 | no runtime observation available |

Незавершённые контроли:
- `MEM-08`: INCONCLUSIVE — profile declares no mechanism; source verification and fixtures pending \(stage D\)
- `TOOL-01`: NOT_EVALUATED — required source\(s\) not bound: \['baseline'\]
- `TOOL-05`: INCONCLUSIVE — 2 text signal\(s\) recorded as hypotheses with fragment, rule and explanation; an imperative, Unicode or a link does not prove malicious intent - review required
- `INV-01`: INCONCLUSIVE — 
- `INV-02`: NOT_EVALUATED — discovery not performed in this mode \(configured catalogue only\)

## 4. Карта компонентов и границ доверия

| Компонент | Тип | Роль | Источники инвентаря | Состояние знания |
|---|---|---|---|---|
| `server:mcp-invest` | mcp_server |  | configured, summary | known |
| `server:agent-native` | native_function |  | configured, summary | known |
| `agent-api` | rest_service | user\_session\_handler | profile | assumed |
| `agent` | agent | user\_session\_handler | profile | assumed |
| `agent-native` | native_function | external\_tool\_host | profile | assumed |
| `session-finalizer` | background_job | background\_worker | profile | assumed |
| `memory-store` | orchestrator | context\_assembler | profile | assumed |
| `mongo` | memory_store | memory\_store | profile | assumed |
| `mongo:agent\_policy\_memories` | memory_store | shared\_policy\_store | profile | assumed |
| `mongo:semantic\_memories` | memory_store | memory\_store | profile | assumed |
| `redis:working` | memory_store | memory\_store | profile | assumed |
| `mcp-invest` | mcp_server | resource\_service | profile | assumed |
| `invest-server` | rest_service | resource\_service | profile | assumed |
| `postgres` | memory_store | data\_store | profile | assumed |
| `keycloak` | identity_provider | identity\_provider | profile | assumed |
| `duckduckgo` | external_provider | external\_provider | profile | assumed |

| Граница | Откуда → куда | Правило | Точка исполнения | Наблюдение |
|---|---|---|---|---|
| `B-user-api` | end\_user → agent-api | principal established by authentication only | agent-api | not_observed |
| `B-agent-mcp` | agent → mcp-invest | subject -\> object authorization for every call | mcp-invest | not_observed |
| `B-mcp-backend` | mcp-invest → invest-server | subject -\> object authorization for every call | invest-server | not_observed |
| `B-mem-publish` | session-finalizer → mongo:agent\_policy\_memories | only policy-admin publishes shared policy | application \+ DB rights | not_observed |
| `B-context` | memory-store → agent | authority marking per context block | MemoryStore.build\_context | not_observed |

Рёбер графа: 22; состояния: publish:static\_path\_supported, scope\_decision:static\_path\_supported, context\_include:static\_path\_supported, memory\_read:static\_path\_supported, memory\_read:static\_path\_supported, memory\_read:static\_path\_supported, derivation:static\_path\_supported, memory\_write:static\_path\_suppor…

| Цепочка | Состояние | Условия |
|---|---|---|
| Недоверенный веб-контент → агент → данные клиента \(MCP\) → внешний поисковый запрос | **static_path_supported** |  |
| Результат инструмента → ответ → рабочая память → финализация → общая политика | **static_path_supported** | LLM extraction marks a fact as scope=global |

Индикатор LETHAL_TRIFECTA: **static\_path\_supported** — Code/configuration connect the three legs under the listed conditions \(static path\).

### Инвентарь

| Сервер | Источник каталога | Handshake | Инструмент | Класс | Операции | Риск возможности | Основание |
|---|---|---|---|---|---|---|---|
| mcp-invest | config | не выполнялся | `instruments\_search` | READ | READ | MEDIUM | source_inference/assumed |
| mcp-invest | config | не выполнялся | `portfolio\_get\_positions\_valuation` | READ | READ | MEDIUM | source_inference/assumed |
| mcp-invest | config | не выполнялся | `portfolio\_presence\_get` | READ | READ | MEDIUM | source_inference/assumed |
| mcp-invest | config | не выполнялся | `register\_tax\_get` | READ | READ | MEDIUM | source_inference/assumed |
| mcp-invest | config | не выполнялся | `client\_operation\_history\_list` | READ | READ | MEDIUM | source_inference/assumed |
| mcp-invest | config | не выполнялся | `client\_training\_list` | READ | READ | MEDIUM | source_inference/assumed |
| mcp-invest | config | не выполнялся | `margin\_instruments\_list` | READ | READ | MEDIUM | source_inference/assumed |
| mcp-invest | config | не выполнялся | `fin\_instrument\_prices\_get` | READ | READ | MEDIUM | source_inference/assumed |
| mcp-invest | config | не выполнялся | `ideas\_list` | READ | READ | MEDIUM | source_inference/assumed |
| agent-native | config | не выполнялся | `duckduckgo\_search` | READ | READ,TRANSMIT | MEDIUM | source_inference/assumed |

Расхождения инвентаря и контрактов:
- mcp-invest: 9 configured vs 14 source\_defined; 9 common; only in configured: -; only in source\_defined: \['bond\_get\_info', 'coupon\_calendar\_list', 'dividend\_calendar\_list', 'emitent\_get\_static\_info', 'margin\_instrument\_get\_info'\]
  - 9/14 is the share of matching names between these two catalogues only - not a percentage of verified security and not a measurement of the running deployment
- mcp-invest: 9 configured vs 14 policy\_authorized; 9 common; only in configured: -; only in policy\_authorized: \['bond\_get\_info', 'coupon\_calendar\_list', 'dividend\_calendar\_list', 'emitent\_get\_static\_info', 'margin\_instrument\_get\_info'\]
  - 9/14 is the share of matching names between these two catalogues only - not a percentage of verified security and not a measurement of the running deployment
- agent-native/duckduckgo\_search: configured vs source\_defined - query: present in configured, absent in source\_defined \(required\); queries: present in source\_defined, absent in configured \(required\)

## 5. Findings: основания и критерии закрытия

### 5.1 Подтверждённые (static_supported / runtime_supported)

- **[CRITICAL (подтверждено: static_supported)] MEM-02 `F-ef5eae79b2` `USER_HANDLER_PUBLISHES_SHARED_POLICY`** — User-session processing is linked to shared policy publication
  - session-finalizer \(role background\_worker\) contains a branch that publishes to mongo:agent\_policy\_memories \(audience shared, authority policy\); trusted publishers: none declared.
  - Корневая причина: publication right is not separated from user-session processing
  - Предпосылки: LLM extraction marks a fact as scope=global
  - Наблюдаемый эффект: не наблюдался; возможный эффект: a user session can shape rules applied to all subjects
  - Основания: claims CL-MEM-02-F-persist-policy; evidence E-c1e3adb492
  - Стадии памяти: W=not_evaluated, R=not_evaluated, C=not_evaluated, B=not_evaluated
  - Исправление: separate the shared-policy publisher; remove publication rights from the user handler at application and DB level Критерий закрытия: user processing holds no publication permission for shared policy; publisher has a distinct principal
  - Ограничения: DB rights of the running deployment not verified; passage of a concrete user text through the extraction step not verified; права БД работающего deployment не проверены; прохождение конкретного пользовательского текста через извлечение фактов не проверено
- **[CRITICAL (подтверждено: static_supported)] AUTH-02 `F-3d561de31c` `RESOURCE_AUTHORIZATION_MISSING`** — Resource authorization not enforced at mcp-invest
  - end\_user -\> mcp-invest -\> READ client\_data\(cus\) -\> invest-server: decision conditional, default not\_enforced; conditions: \['MCP\_INVEST\_AUTH\_MODE=vulnerable \(compose default\): check\_cus\_access returns without checking', 'X-Demo-Auth-Mode selects the mode per request'\].
  - Предпосылки: MCP\_INVEST\_AUTH\_MODE=vulnerable \(compose default\): check\_cus\_access returns without checking; X-Demo-Auth-Mode selects the mode per request
  - Наблюдаемый эффект: не наблюдался; возможный эффект: a valid token grants access to any object \(IDOR / BAC delegated to the model\)
  - Основания: claims CL-AUTH-02-T2-agent-mcp; evidence E-0a803c01e7
  - Исправление: check subject -\> object permission at this hop, including client -\> account -\> operation relations Критерий закрытия: each receiving service decides authorization for the concrete object; foreign-object fixture is refused at this hop
  - Ограничения: an entry-API refusal does not cover a backend the request never reached
- **[CRITICAL (подтверждено: static_supported)] AUTH-02 `F-974158ed15` `RESOURCE_AUTHORIZATION_MISSING`** — Resource authorization not enforced at invest-server
  - end\_user -\> invest-server -\> READ client\_data\(cus\) -\> postgres: decision conditional, default not\_enforced; conditions: \['INVEST\_SERVER\_AUTH\_MODE=vulnerable \(compose default\)', 'X-Demo-Auth-Mode forwarded by mcp-invest'\].
  - Предпосылки: INVEST\_SERVER\_AUTH\_MODE=vulnerable \(compose default\); X-Demo-Auth-Mode forwarded by mcp-invest
  - Наблюдаемый эффект: не наблюдался; возможный эффект: a valid token grants access to any object \(IDOR / BAC delegated to the model\)
  - Основания: claims CL-AUTH-02-T3-mcp-backend; evidence E-60b6143c8c
  - Исправление: check subject -\> object permission at this hop, including client -\> account -\> operation relations Критерий закрытия: each receiving service decides authorization for the concrete object; foreign-object fixture is refused at this hop
  - Ограничения: an entry-API refusal does not cover a backend the request never reached
- **[CRITICAL (подтверждено: static_supported)] AUTH-02 `F-c3ac7ea94b` `RESOURCE_AUTHORIZATION_MISSING`** — Resource authorization not enforced at invest-server
  - end\_user -\> invest-server -\> READ account\_data\(account\_id\) -\> postgres: decision conditional, default not\_enforced; conditions: \['INVEST\_SERVER\_AUTH\_MODE=vulnerable \(compose default\)'\].
  - Предпосылки: INVEST\_SERVER\_AUTH\_MODE=vulnerable \(compose default\)
  - Наблюдаемый эффект: не наблюдался; возможный эффект: a valid token grants access to any object \(IDOR / BAC delegated to the model\)
  - Основания: claims CL-AUTH-02-T3b-account-owner; evidence E-7e61565950
  - Исправление: check subject -\> object permission at this hop, including client -\> account -\> operation relations Критерий закрытия: each receiving service decides authorization for the concrete object; foreign-object fixture is refused at this hop
  - Ограничения: an entry-API refusal does not cover a backend the request never reached
- **[CRITICAL (подтверждено: static_supported)] AUTH-03 `F-96ac946f83` `CLIENT_CAN_WEAKEN_SERVER_POLICY`** — Client parameters weaken mandatory server checks at agent-api
  - agent-api: \['body.auth\_mode \(default vulnerable\)'\] select\(s\) the security profile per request; affected transitions/flows: \['T1-user-api', 'F-security-mode-body'\]; mandatory checks: \['resource\_authorization', 'subject\_bound\_delegation', 'token\_audience'\].
  - Наблюдаемый эффект: не наблюдался; возможный эффект: -
  - Основания: claims CL-AUTH-03-agent-api; evidence E-4a9897a36f, E-ff0f6dafef
  - Исправление: fix the mandatory profile server-side; ignore client mode parameters in protected deployments Критерий закрытия: the server defines mandatory checks; a client mode parameter cannot relax them \(fixture\)
- **[CRITICAL (подтверждено: static_supported)] AUTH-03 `F-cc44e3d173` `CLIENT_CAN_WEAKEN_SERVER_POLICY`** — Client parameters weaken mandatory server checks at mcp-invest
  - mcp-invest: \['header X-Demo-Auth-Mode'\] select\(s\) the security profile per request; affected transitions/flows: \['T2-agent-mcp', 'F-security-mode-header'\]; mandatory checks: \['resource\_authorization', 'subject\_bound\_delegation', 'token\_audience'\].
  - Наблюдаемый эффект: не наблюдался; возможный эффект: -
  - Основания: claims CL-AUTH-03-mcp-invest; evidence E-0a803c01e7, E-9501ca2be1
  - Исправление: fix the mandatory profile server-side; ignore client mode parameters in protected deployments Критерий закрытия: the server defines mandatory checks; a client mode parameter cannot relax them \(fixture\)
- **[CRITICAL (подтверждено: static_supported)] AUTH-03 `F-485f6ad0df` `CLIENT_CAN_WEAKEN_SERVER_POLICY`** — Client parameters weaken mandatory server checks at invest-server
  - invest-server: client-controlled mode select\(s\) the security profile per request; affected transitions/flows: \['T3-mcp-backend', 'T3b-account-owner'\]; mandatory checks: \['resource\_authorization', 'subject\_bound\_delegation', 'token\_audience'\].
  - Наблюдаемый эффект: не наблюдался; возможный эффект: -
  - Основания: claims CL-AUTH-03-invest-server; evidence E-60b6143c8c, E-7e61565950
  - Исправление: fix the mandatory profile server-side; ignore client mode parameters in protected deployments Критерий закрытия: the server defines mandatory checks; a client mode parameter cannot relax them \(fixture\)
- **[CRITICAL (подтверждено: static_supported)] AUTH-05 `F-c9b97e6334` `UNBOUNDED_DELEGATION`** — Service credentials bypass end-user restrictions at agent
  - agent calls mcp-invest with service\_account\_unrestricted; conditions: \['auth\_mode=vulnerable \(default\)'\].
  - Предпосылки: auth\_mode=vulnerable \(default\)
  - Наблюдаемый эффект: не наблюдался; возможный эффект: -
  - Основания: claims CL-AUTH-05-T4-agent-token; evidence E-a2ff9df05e
  - Исправление: delegate with subject-bound tokens \(token exchange / on-behalf-of\) scoped to the task and resource Критерий закрытия: downstream calls carry the end-user binding; a service token alone is refused for user resources
- **[HIGH (подтверждено: static_supported)] MEM-03 `F-eb603c8b4a` `SCOPE_DECIDED_BY_UNTRUSTED_SOURCE`** — Memory owner / audience decided by an untrusted source
  - session-finalizer takes the audience of 'shared\_policy' from llm\_output; validation: range check \(user\|global\) only.
  - Наблюдаемый эффект: не наблюдался; возможный эффект: metadata produced by a model or external content sets write authority
  - Основания: claims CL-MEM-03-F-scope-from-llm; evidence E-c1e3adb492
  - Исправление: resolve owner and audience server-side from the authenticated principal and policy Критерий закрытия: proposed scope from model/external content is advisory only; the server decides
- **[HIGH (подтверждено: static_supported)] MEM-04 `F-066fafcc1b` `MEMORY_PRESENTED_AS_RULES`** — Memory content presented as rules without content authority
  - memory-store includes 'shared\_policy' in the system role as rules; policy authority for the type: policy, publisher trusted: False.
  - Наблюдаемый эффект: не наблюдался; возможный эффект: reference data or user-derived text gains instruction authority
  - Основания: claims CL-MEM-04-F-context-policy-as-rules; evidence E-ec5b11d7cd
  - Стадии памяти: W=not_evaluated, R=not_evaluated, C=not_evaluated, B=not_evaluated
  - Исправление: mark memory blocks by authority; only trusted-publisher records may be presented as rules Критерий закрытия: context assembly separates data blocks from instruction blocks and records the authority of each
- **[HIGH (подтверждено: static_supported)] MEM-06 `F-2a34099aa7` `AUTOMATIC_TRUST_ELEVATION`** — Retelling or model confidence acts as publication permission
  - session-finalizer: Пересказ модели и её confidence становятся общей политикой без отдельного разрешённого перехода. \(mechanism: LLM-reported confidence is stored as the record's confidence; no review/approval transition before shared publication; review required by policy: True\).
  - Наблюдаемый эффект: не наблюдался; возможный эффект: a paraphrase by the assistant or a high model confidence value becomes shared truth
  - Основания: claims CL-MEM-06-F-trust-elevation-confidence; evidence E-c1e3adb492
  - Исправление: require an authorized review/approval transition before shared publication; ignore self-reported confidence for authority Критерий закрытия: shared records carry review\_state=approved with an approval\_ref from a trusted publisher
- **[HIGH (подтверждено: static_supported)] MEM-06 `F-864c303962` `AUTOMATIC_TRUST_ELEVATION`** — Shared publication without an approval transition
  - session-finalizer: Обработка извлечённых фактов пользовательской сессии содержит ветвь записи общей политики \(AgentPolicyMemory\). \(mechanism: no approval; review required by policy: True\).
  - Наблюдаемый эффект: не наблюдался; возможный эффект: a paraphrase by the assistant or a high model confidence value becomes shared truth
  - Основания: claims CL-MEM-06-F-persist-policy; evidence E-c1e3adb492
  - Исправление: require an authorized review/approval transition before shared publication; ignore self-reported confidence for authority Критерий закрытия: shared records carry review\_state=approved with an approval\_ref from a trusted publisher
- **[HIGH (подтверждено: static_supported)] INFRA-01 `F-d4c5f187ec` `EXCESSIVE_STORE_RIGHTS`** — agent-api holds rights on mongo:agent\_policy\_memories beyond policy
  - observed \['publish', 'read', 'write'\], policy allows \['read'\].
  - Наблюдаемый эффект: не наблюдался; возможный эффект: -
  - Основания: claims CL-INFRA-01-F-store-access-policy; evidence E-a5ec992c02
  - Исправление: grant per-service store credentials with least privilege; keep shared-policy publication on a separate principal Критерий закрытия: service rights on memory stores match policy; publication is a separate credential
- **[HIGH (подтверждено: static_supported)] INFRA-02 `F-4cfa945006` `STORAGE_PUBLISHED_ON_HOST`** — redis storage port published on the host
  - redis \(redis\) publishes port\(s\) \['6379'\] on the host; policy forbids storage publication.
  - Наблюдаемый эффект: не наблюдался; возможный эффект: direct access to memory/data stores from the host network zone; combined with missing auth, full read/write
  - Основания: claims CL-INFRA-02-redis; evidence E-accb7535b7
  - Исправление: remove host publication, isolate storage networks, enable authentication and least-privilege service users Критерий закрытия: storage ports are not published; reachability from external zones is refused \(observed per zone\)
  - Ограничения: reachability from specific external zones not established
- **[HIGH (подтверждено: static_supported)] INFRA-02 `F-a23c2cf23d` `STORAGE_PUBLISHED_ON_HOST`** — mongo storage port published on the host
  - mongo \(mongodb\) publishes port\(s\) \['27017'\] on the host; policy forbids storage publication.
  - Наблюдаемый эффект: не наблюдался; возможный эффект: direct access to memory/data stores from the host network zone; combined with missing auth, full read/write
  - Основания: claims CL-INFRA-02-mongo; evidence E-13933d746a
  - Исправление: remove host publication, isolate storage networks, enable authentication and least-privilege service users Критерий закрытия: storage ports are not published; reachability from external zones is refused \(observed per zone\)
  - Ограничения: reachability from specific external zones not established
- **[HIGH (подтверждено: static_supported)] TOOL-04 `F-be38f8e6b7` `TOOL_RESULT_REACHES_POLICY`** — Tool results can influence shared memory / policy
  - chain \['duckduckgo', 'agent', 'redis:working', 'session-finalizer', 'mongo:agent\_policy\_memories'\] is static\_path\_supported; conditions: \['LLM extraction marks a fact as scope=global'\].
  - Предпосылки: LLM extraction marks a fact as scope=global
  - Наблюдаемый эффект: не наблюдался; возможный эффект: content returned by a tool is transformed and published as shared rules
  - Основания: claims CL-TOOL-04-tool-result-to-policy; evidence E-2c64becd47, E-c1e3adb492, E-e8da8f9c04
  - Исправление: keep tool results as data through derivation; publication of policy needs a separate authorized process Критерий закрытия: no derivation path from tool results to shared policy without an authorized review
- **[HIGH (подтверждено: static_supported)] AUTH-04 `F-95ab9aadae` `TOKEN_VALIDATION_INCOMPLETE`** — mcp-invest: token validation skips audience
  - scheme jwt requires \['signature', 'issuer', 'audience', 'expiry', 'algorithm'\]; observed \{'signature': True, 'issuer': True, 'audience': False, 'expiry': True, 'algorithm': True\}.
  - Наблюдаемый эффект: не наблюдался; возможный эффект: a token issued for another audience/issuer is accepted by this service
  - Основания: claims CL-AUTH-04-mcp-invest; evidence E-77f12a2234
  - Исправление: validate issuer, audience, signature, expiry and algorithm against trusted config of this service Критерий закрытия: each receiving service rejects tokens with a foreign issuer/audience \(fixture\)
- **[HIGH (подтверждено: static_supported)] AUTH-04 `F-b10c949fb6` `TOKEN_VALIDATION_INCOMPLETE`** — invest-server: token validation skips audience
  - scheme jwt requires \['signature', 'issuer', 'audience', 'expiry', 'algorithm'\]; observed \{'signature': True, 'issuer': True, 'audience': False, 'expiry': True, 'algorithm': True\}.
  - Наблюдаемый эффект: не наблюдался; возможный эффект: a token issued for another audience/issuer is accepted by this service
  - Основания: claims CL-AUTH-04-invest-server; evidence E-31a00dd9fb
  - Исправление: validate issuer, audience, signature, expiry and algorithm against trusted config of this service Критерий закрытия: each receiving service rejects tokens with a foreign issuer/audience \(fixture\)
- **[HIGH (подтверждено: static_supported)] AUTH-04 `F-16e42e7d4e` `TOKEN_VALIDATION_INCOMPLETE`** — agent-api: token validation skips issuer, audience
  - scheme jwt requires \['signature', 'issuer', 'audience', 'expiry', 'algorithm'\]; observed \{'signature': True, 'issuer': False, 'audience': False, 'expiry': True, 'algorithm': True\}.
  - Наблюдаемый эффект: не наблюдался; возможный эффект: a token issued for another audience/issuer is accepted by this service
  - Основания: claims CL-AUTH-04-agent-api; evidence E-10786f1d2f
  - Исправление: validate issuer, audience, signature, expiry and algorithm against trusted config of this service Критерий закрытия: each receiving service rejects tokens with a foreign issuer/audience \(fixture\)
- **[HIGH (подтверждено: static_supported)] EGRESS-01 `F-c2c7b528ad` `EGRESS_DATA_CATEGORY_UNCONTROLLED`** — Uncontrolled transmission to duckduckgo
  - destination duckduckgo allowed, but categories \['client\_identifier', 'portfolio\_data'\] can be transmitted without a filter.
  - Наблюдаемый эффект: не наблюдался; возможный эффект: client identifiers or portfolio data reach an external provider inside a query
  - Основания: claims CL-EGRESS-01-F-search-transmit; evidence E-dd35524719
  - Исправление: control both destination and data category; filter model-composed queries before transmission Критерий закрытия: egress policy is enforced for destination and category; fixture observes the actual payload locally
- **[MEDIUM (подтверждено: static_supported)] MEM-05 `F-a9b2c57941` `PROVENANCE_LOST`** — Derived memory loses its parents
  - session-finalizer -\> mongo:semantic\_memories: Производные факты хранят только ссылку на сессию/первый эпизод; связь с сообщениями и результатами инструментов теряется.; kept fields: \['source\_episode\_id \(first episode only\)', 'source\_session\_id \(policy, audit only\)'\].
  - Наблюдаемый эффект: не наблюдался; возможный эффект: tool results and untrusted fragments cannot be traced into derived memory; revocation cannot reach derivatives
  - Основания: claims CL-MEM-05-F-derive-facts; evidence E-c1e3adb492
  - Исправление: link derived records to all parent events and transformation versions; make lost lineage visible Критерий закрытия: every derived record carries source\_event\_refs / derived\_from or an explicit lineage\_completeness=lost
- **[MEDIUM (подтверждено: static_supported)] MEM-05 `F-ffdfd92481` `PROVENANCE_LOST`** — Derived memory loses its parents
  - agent -\> redis:working: В рабочую память пишутся запрос и финальный ответ, а не сырые результаты инструментов: для связи tool result → memory нужна прослеживаемость производного ответа.; kept fields: none.
  - Наблюдаемый эффект: не наблюдался; возможный эффект: tool results and untrusted fragments cannot be traced into derived memory; revocation cannot reach derivatives
  - Основания: claims CL-MEM-05-F-answer-to-working; evidence E-e8da8f9c04
  - Исправление: link derived records to all parent events and transformation versions; make lost lineage visible Критерий закрытия: every derived record carries source\_event\_refs / derived\_from or an explicit lineage\_completeness=lost
- **[MEDIUM (подтверждено: static_supported)] TOOL-02 `F-b366e3d23f` `CONTRACT_MISMATCH`** (agent-native/duckduckgo\_search) — Operation contract mismatch: agent-native/duckduckgo\_search
  - agent-native/duckduckgo\_search: configured vs source\_defined - query: present in configured, absent in source\_defined \(required\); queries: present in source\_defined, absent in configured \(required\)
  - Наблюдаемый эффект: не наблюдался; возможный эффект: a check written against the stale schema fails on arguments before reaching the control under test
  - Основания: claims CL-TOOL-02-agent-native/duckduckgo\_search; evidence E-ae129c839f
  - Исправление: align the configured/agreed schema with the build; version the contract Критерий закрытия: configured, source-defined and live schemas agree for the tool \(names, required, types\)
- **[MEDIUM (подтверждено: static_supported)] MEM-09 `F-fd0eac557e` `BACKGROUND_JOB_CONSISTENCY`** — Background job J-finalize lacks consistency guarantees
  - session-finalizer: not idempotent \(retries can duplicate publications\); does not check the policy revision \(can publish cancelled data\).
  - Наблюдаемый эффект: не наблюдался; возможный эффект: -
  - Основания: claims CL-MEM-09-J-finalize; evidence E-ef2a903aa2
  - Исправление: carry job/parent ids, idempotency keys and the policy revision through background processing Критерий закрытия: retries, concurrent sessions and delayed jobs keep the original identity and skip cancelled data \(fixture\)
  - Ограничения: stage D: runtime job events \(job ids, parent ids\) are on the roadmap
- **[MEDIUM (подтверждено: static_supported)] MEM-10 `F-5ff05000e5` `RETENTION_UNDEFINED_OR_EXCEEDED`** — Retention for memory type user\_fact is undefined or exceeds policy
  - policy expects ttl\<=31536000s; observed ttl=None \(mechanism none\).
  - Наблюдаемый эффект: не наблюдался; возможный эффект: -
  - Основания: claims CL-MEM-10-user\_fact; evidence E-2e56c59cee
  - Исправление: define TTL, volume limits, refresh and cleanup per memory type; prevent uncontrolled restoration Критерий закрытия: each memory type has a retention policy in config and a cleanup mechanism with maintenance events
  - Ограничения: stage D: maintenance events are on the roadmap
- **[MEDIUM (подтверждено: static_supported)] MEM-10 `F-60668b9ae2` `RETENTION_UNDEFINED_OR_EXCEEDED`** — Retention for memory type shared\_policy is undefined or exceeds policy
  - policy expects ttl\<=7776000s; observed ttl=None \(mechanism none\).
  - Наблюдаемый эффект: не наблюдался; возможный эффект: -
  - Основания: claims CL-MEM-10-shared\_policy; evidence E-f497653645
  - Исправление: define TTL, volume limits, refresh and cleanup per memory type; prevent uncontrolled restoration Критерий закрытия: each memory type has a retention policy in config and a cleanup mechanism with maintenance events
  - Ограничения: stage D: maintenance events are on the roadmap

### 5.2 Гипотезы и сигналы (требуют разбора; не являются подтверждённым нарушением)

- **[потенциально HIGH (гипотеза: hypothesis)] TOOL-05 `F-665097ecae` `AUTHORIZATION_STEERING`** (mcp-invest/portfolio\_get\_positions\_valuation) — Parameter description steers the model to pass an arbitrary identifier \(IDOR / broken access control\)
  - Parameter description steers the model to pass an arbitrary identifier \(IDOR / broken access control\) in description: 'значение из поля user\_id текущего чата или любое другое'
  - Ограничения: text heuristic: the signal is a hypothesis, not proof of compromise or of a right to change the server
- **[потенциально MEDIUM (гипотеза: hypothesis)] TOOL-05 `F-2d71e63939` `MODEL_ADDRESSED_IMPERATIVE`** (mcp-invest/instruments\_search) — Imperative addressed to the model
  - Imperative addressed to the model in description: 'Используй этот тул первым'
  - Ограничения: text heuristic: the signal is a hypothesis, not proof of compromise or of a right to change the server
- **[потенциально MEDIUM (гипотеза: hypothesis)] MEM-08 `F-3a09a63a4b` `REVOCATION_MECHANISM_MISSING`** — No revocation / derived-data withdrawal mechanism
  - the system declares no revocation mechanism while policy requires propagation to derived records
  - Ограничения: stage D: revocation fixtures and index-version tracking are on the roadmap
- **[потенциально MEDIUM (гипотеза: hypothesis)] INV-01 `F-5a85937de0` `INVENTORY_MISMATCH`** (mcp-invest) — Inventory mismatch for mcp-invest \(configured/source\_defined\)
  - mcp-invest: 9 configured vs 14 source\_defined; 9 common; only in configured: -; only in source\_defined: \['bond\_get\_info', 'coupon\_calendar\_list', 'dividend\_calendar\_list', 'emitent\_get\_static\_info', 'margin\_instrument\_get\_info'\]; unexplained: \['bond\_get\_info', 'coupon\_calendar\_list', 'dividend\_calendar\_list', 'emitent\_get\_static\_info', 'margin\_instrument\_get\_info'\].
  - Ограничения: a mismatch is not automatically a hidden tool; reasons may be legitimate

## 6. Результаты памяти по стадиям W/R/C/B

Стадийные наблюдения памяти не проводились (нет случаев/трасс): W/R/C/B = not_evaluated.

| Правило | Применимость | Выполнение | Исход | Интерпретация |
|---|---|---|---|---|
| MEM-01 | applicable | completed | **PASS** |  |
| MEM-02 | applicable | completed | **FAIL** |  |
| MEM-03 | applicable | completed | **FAIL** |  |
| MEM-04 | applicable | completed | **FAIL** |  |
| MEM-05 | applicable | completed | **FAIL** |  |
| MEM-06 | applicable | completed | **FAIL** |  |
| MEM-07 | applicable | completed | **PASS** |  |
| MEM-08 | applicable | completed | **INCONCLUSIVE** | profile declares no mechanism; source verification and fixtures pending \(stage D\) |
| MEM-09 | applicable | completed | **FAIL** |  |
| MEM-10 | applicable | completed | **FAIL** |  |

## 7. Результаты авторизации и исходящих эффектов

| Правило | Применимость | Выполнение | Исход | Границы | Интерпретация |
|---|---|---|---|---|---|
| AUTH-01 | applicable | completed | **PASS** |  |  |
| AUTH-02 | applicable | completed | **FAIL** | B-agent-mcp, B-mcp-backend, B-user-api | each hop evaluated separately; a refusal at one hop does not cover the next |
| AUTH-03 | applicable | completed | **FAIL** |  |  |
| AUTH-04 | applicable | completed | **FAIL** |  |  |
| AUTH-05 | applicable | completed | **FAIL** |  |  |
| AUTH-06 | applicable | completed | **PASS** |  |  |
| INFRA-01 | applicable | completed | **FAIL** |  |  |
| INFRA-02 | applicable | completed | **FAIL** |  | bind, publication, routing and filtering are separate facts; only publication is observed here |
| INFRA-03 | not_applicable | skipped | **NOT_APPLICABLE** |  | no controlled validation in this mode |
| TOOL-01 | applicable | skipped | **NOT_EVALUATED** |  | required source\(s\) not bound: \['baseline'\] |
| TOOL-02 | applicable | completed | **FAIL** |  | 8 consistent, 1 mismatched contract\(s\) |
| TOOL-03 | applicable | completed | **PASS** |  | router namespace: flat; 0 name collision\(s\) |
| TOOL-04 | applicable | completed | **FAIL** |  |  |
| TOOL-05 | applicable | completed | **INCONCLUSIVE** |  | 2 text signal\(s\) recorded as hypotheses with fragment, rule and explanation; an imperative, Unicode or a link does not prove malicious intent - review required |
| EGRESS-01 | applicable | completed | **FAIL** |  |  |
| EGRESS-02 | not_applicable | skipped | **NOT_APPLICABLE** |  | no controlled validation in this mode |
| INV-01 | applicable | completed | **INCONCLUSIVE** |  |  |
| INV-02 | applicable | skipped | **NOT_EVALUATED** |  | discovery not performed in this mode \(configured catalogue only\) |

## 8. Изменения относительно совместимого baseline

Baseline не задан; сравнение не выполнялось.

## 9. План исправлений, повторная оценка и ограничения

| Приоритет | Finding | Исправление | Критерий закрытия |
|---|---|---|---|
| P0 | `F-ef5eae79b2` | separate the shared-policy publisher; remove publication rights from the user handler at application and DB level | user processing holds no publication permission for shared policy; publisher has a distinct principal |
| P0 | `F-3d561de31c` | check subject -\> object permission at this hop, including client -\> account -\> operation relations | each receiving service decides authorization for the concrete object; foreign-object fixture is refused at this hop |
| P0 | `F-974158ed15` | check subject -\> object permission at this hop, including client -\> account -\> operation relations | each receiving service decides authorization for the concrete object; foreign-object fixture is refused at this hop |
| P0 | `F-c3ac7ea94b` | check subject -\> object permission at this hop, including client -\> account -\> operation relations | each receiving service decides authorization for the concrete object; foreign-object fixture is refused at this hop |
| P0 | `F-96ac946f83` | fix the mandatory profile server-side; ignore client mode parameters in protected deployments | the server defines mandatory checks; a client mode parameter cannot relax them \(fixture\) |
| P0 | `F-cc44e3d173` | fix the mandatory profile server-side; ignore client mode parameters in protected deployments | the server defines mandatory checks; a client mode parameter cannot relax them \(fixture\) |
| P0 | `F-485f6ad0df` | fix the mandatory profile server-side; ignore client mode parameters in protected deployments | the server defines mandatory checks; a client mode parameter cannot relax them \(fixture\) |
| P0 | `F-c9b97e6334` | delegate with subject-bound tokens \(token exchange / on-behalf-of\) scoped to the task and resource | downstream calls carry the end-user binding; a service token alone is refused for user resources |
| P0 | `F-eb603c8b4a` | resolve owner and audience server-side from the authenticated principal and policy | proposed scope from model/external content is advisory only; the server decides |
| P0 | `F-066fafcc1b` | mark memory blocks by authority; only trusted-publisher records may be presented as rules | context assembly separates data blocks from instruction blocks and records the authority of each |
| P0 | `F-2a34099aa7` | require an authorized review/approval transition before shared publication; ignore self-reported confidence for authority | shared records carry review\_state=approved with an approval\_ref from a trusted publisher |
| P0 | `F-864c303962` | require an authorized review/approval transition before shared publication; ignore self-reported confidence for authority | shared records carry review\_state=approved with an approval\_ref from a trusted publisher |
| P0 | `F-d4c5f187ec` | grant per-service store credentials with least privilege; keep shared-policy publication on a separate principal | service rights on memory stores match policy; publication is a separate credential |
| P0 | `F-4cfa945006` | remove host publication, isolate storage networks, enable authentication and least-privilege service users | storage ports are not published; reachability from external zones is refused \(observed per zone\) |
| P0 | `F-a23c2cf23d` | remove host publication, isolate storage networks, enable authentication and least-privilege service users | storage ports are not published; reachability from external zones is refused \(observed per zone\) |
| P0 | `F-be38f8e6b7` | keep tool results as data through derivation; publication of policy needs a separate authorized process | no derivation path from tool results to shared policy without an authorized review |
| P1 | `F-95ab9aadae` | validate issuer, audience, signature, expiry and algorithm against trusted config of this service | each receiving service rejects tokens with a foreign issuer/audience \(fixture\) |
| P1 | `F-b10c949fb6` | validate issuer, audience, signature, expiry and algorithm against trusted config of this service | each receiving service rejects tokens with a foreign issuer/audience \(fixture\) |
| P1 | `F-16e42e7d4e` | validate issuer, audience, signature, expiry and algorithm against trusted config of this service | each receiving service rejects tokens with a foreign issuer/audience \(fixture\) |
| P1 | `F-c2c7b528ad` | control both destination and data category; filter model-composed queries before transmission | egress policy is enforced for destination and category; fixture observes the actual payload locally |
| P1 | `F-a9b2c57941` | link derived records to all parent events and transformation versions; make lost lineage visible | every derived record carries source\_event\_refs / derived\_from or an explicit lineage\_completeness=lost |
| P1 | `F-ffdfd92481` | link derived records to all parent events and transformation versions; make lost lineage visible | every derived record carries source\_event\_refs / derived\_from or an explicit lineage\_completeness=lost |
| P1 | `F-b366e3d23f` | align the configured/agreed schema with the build; version the contract | configured, source-defined and live schemas agree for the tool \(names, required, types\) |
| P2 | `F-fd0eac557e` | carry job/parent ids, idempotency keys and the policy revision through background processing | retries, concurrent sessions and delayed jobs keep the original identity and skip cancelled data \(fixture\) |
| P2 | `F-5ff05000e5` | define TTL, volume limits, refresh and cleanup per memory type; prevent uncontrolled restoration | each memory type has a retention policy in config and a cleanup mechanism with maintenance events |
| P2 | `F-60668b9ae2` | define TTL, volume limits, refresh and cleanup per memory type; prevent uncontrolled restoration | each memory type has a retention policy in config and a cleanup mechanism with maintenance events |

Ограничения оценки:
- MEM-08: INCONCLUSIVE \(profile declares no mechanism; source verification and fixtures pending \(stage D\)\)
- TOOL-01: NOT\_EVALUATED \(required source\(s\) not bound: \['baseline'\]\)
- TOOL-05: INCONCLUSIVE \(2 text signal\(s\) recorded as hypotheses with fragment, rule and explanation; an imperative, Unicode or a link does not prove malicious intent - review required\)
- INV-01: INCONCLUSIVE \(\)
- INV-02: NOT\_EVALUATED \(discovery not performed in this mode \(configured catalogue only\)\)
- no runtime validation was performed: all supported claims are static \(config, definitions, source, policy\)

## 10. Реестр свидетельств и версий правил

Свидетельств: 67; утверждений: 75; правила: 2.0.0

| ID | Источник | Метод | Локатор | Ограничения |
|---|---|---|---|---|
| `E-44af7c2a5f` | config | parsing | path=examples/genai\_invest\_stand.config.json, kind=mcp\_config |  |
| `E-72ee80d939` | definition | parsing | path=examples/genai\_invest\_stand.config.json, server=mcp-invest, inventory=configured | configured catalogue: what the client config lists, not what a server advertises |
| `E-c4a7110460` | definition | parsing | path=examples/genai\_invest\_stand.config.json, server=agent-native, inventory=configured | configured catalogue: what the client config lists, not what a server advertises |
| `E-c1e3adb492` | source_code | static_analysis | path=app/orchestrator/graph.py, symbol=persist\_all, lines=\[91, 143\] |  |
| `E-ec5b11d7cd` | source_code | static_analysis | path=app/memory/store.py, symbol=MemoryStore.build\_context, lines=\[22, 76\] |  |
| `E-a4a8124e29` | source_code | static_analysis | path=app/memory/mongo.py, symbol=SemanticRepo.list\_for\_context, lines=\[103, 114\] |  |
| `E-f96c104563` | source_code | static_analysis | path=app/memory/mongo.py, symbol=DialogRepo.list\_for\_user, lines=\[59, 69\] |  |
| `E-d7fa0227fa` | source_code | static_analysis | path=app/memory/mongo.py, symbol=EpisodicRepo.list\_for\_user, lines=\[81, 91\] |  |
| `E-a00c85dbac` | source_code | static_analysis | path=app/memory/mongo.py, symbol=AgentPolicyRepo.list\_all, lines=\[130, 136\] |  |
| `E-e8da8f9c04` | source_code | static_analysis | path=app/agent/runner.py, symbol=run\_research, lines=\[163, 230\] |  |
| `E-2c64becd47` | source_code | static_analysis | path=app/orchestrator/graph.py, symbol=load\_working, lines=\[55, 59\] |  |
| `E-e278afe712` | source_code | static_analysis | path=app/agent/runner.py, symbol=\_load\_tools, lines=\[129, 148\] |  |
| `E-dd35524719` | source_code | static_analysis | path=app/agent/tools.py, symbol=duckduckgo\_search, lines=\[19, 46\] |  |
| `E-27e42ee05d` | source_code | static_analysis | path=app/api\_server.py, symbol=\_resolve\_user, lines=\[228, 235\] |  |
| `E-10786f1d2f` | source_code | static_analysis | path=app/api\_server.py, symbol=\_current\_identity, lines=\[48, 69\] |  |
| `E-ff0f6dafef` | source_code | static_analysis | path=app/api\_server.py, symbol=ChatCompletionRequest, lines=\[219, 225\] |  |
| `E-9501ca2be1` | source_code | static_analysis | path=mcp-invest/server.py, symbol=\_demo\_mode, lines=\[37, 40\] |  |
| `E-a5ec992c02` | source_code | static_analysis | path=app/memory/store.py, symbol=MemoryStore.save\_agent\_policy, lines=\[111, 112\] |  |
| `E-6f64a672cc` | source_code | static_analysis | path=app/memory/mongo.py, symbol=ApiKeyRepo.find\_by\_hash, lines=\[148, 153\] |  |
| `E-0a8e6cff5e` | source_code | static_analysis | path=app/memory/working.py, symbol=WorkingMemoryStore.save, lines=\[31, 41\] |  |
| `E-f497653645` | source_code | static_analysis | path=app/memory/mongo.py, symbol=AgentPolicyRepo, lines=\[117, 136\] |  |
| `E-2e56c59cee` | source_code | static_analysis | path=app/memory/mongo.py, symbol=SemanticRepo, lines=\[94, 114\] |  |
| `E-4a9897a36f` | source_code | static_analysis | path=app/api\_server.py, symbol=chat\_completions, lines=\[330, 383\] |  |
| `E-0a803c01e7` | source_code | static_analysis | path=mcp-invest/server.py, symbol=\_check\_cus, lines=\[51, 56\] |  |
| `E-60b6143c8c` | source_code | static_analysis | path=invest-server/main.py, symbol=get\_client, lines=\[43, 53\] |  |
| `E-7e61565950` | source_code | static_analysis | path=invest-server/main.py, symbol=get\_tax, lines=\[72, 84\] |  |
| `E-a2ff9df05e` | source_code | static_analysis | path=app/agent/runner.py, symbol=\_mcp\_headers, lines=\[109, 126\] |  |
| `E-6ef3fa52f9` | source_code | static_analysis | path=app/agent/runner.py, symbol=\_exchange\_token, lines=\[73, 87\] |  |
| `E-ef2a903aa2` | source_code | static_analysis | path=app/orchestrator/graph.py, symbol=finalize\_session, lines=\[170, 174\] |  |
| `E-86229b7c5d` | source_code | static_analysis | path=app/memory/mongo.py, symbol=\_doc\_trusted, lines=\[167, 172\] |  |
| `E-77f12a2234` | source_code | static_analysis | path=mcp-invest/auth.py, symbol=validate\_token, lines=\[32, 50\] |  |
| `E-31a00dd9fb` | source_code | static_analysis | path=invest-server/auth.py, symbol=validate\_token, lines=\[35, 53\] |  |
| `E-022f04d3cb` | source_code | static_analysis | path=mcp-invest/server.py, symbol=instruments\_search, lines=\[60, 77\], declaration=instruments\_search |  |
| `E-61f8bd1307` | source_code | static_analysis | path=mcp-invest/server.py, symbol=portfolio\_get\_positions\_valuation, lines=\[81, 129\], declaration=portfolio\_get\_p… |  |
| `E-b368934de6` | source_code | static_analysis | path=mcp-invest/server.py, symbol=portfolio\_presence\_get, lines=\[133, 154\], declaration=portfolio\_presence\_get |  |
| `E-04798a0f2f` | source_code | static_analysis | path=mcp-invest/server.py, symbol=register\_tax\_get, lines=\[158, 174\], declaration=register\_tax\_get |  |
| `E-6fa8027f6a` | source_code | static_analysis | path=mcp-invest/server.py, symbol=client\_operation\_history\_list, lines=\[178, 198\], declaration=client\_operation\_h… |  |
| `E-1265fedefe` | source_code | static_analysis | path=mcp-invest/server.py, symbol=margin\_instruments\_list, lines=\[202, 229\], declaration=margin\_instruments\_list |  |
| `E-6a8e761a06` | source_code | static_analysis | path=mcp-invest/server.py, symbol=margin\_instrument\_get\_info, lines=\[233, 247\], declaration=margin\_instrument\_get… |  |
| `E-aea921cfed` | source_code | static_analysis | path=mcp-invest/server.py, symbol=client\_training\_list, lines=\[251, 261\], declaration=client\_training\_list |  |
| `E-a839e18a39` | source_code | static_analysis | path=mcp-invest/server.py, symbol=dividend\_calendar\_list, lines=\[265, 283\], declaration=dividend\_calendar\_list |  |
| `E-2ac7d9bb5b` | source_code | static_analysis | path=mcp-invest/server.py, symbol=coupon\_calendar\_list, lines=\[287, 293\], declaration=coupon\_calendar\_list |  |
| `E-c54d75536d` | source_code | static_analysis | path=mcp-invest/server.py, symbol=bond\_get\_info, lines=\[297, 310\], declaration=bond\_get\_info |  |
| `E-ec48dbee28` | source_code | static_analysis | path=mcp-invest/server.py, symbol=emitent\_get\_static\_info, lines=\[314, 322\], declaration=emitent\_get\_static\_info |  |
| `E-560869bdac` | source_code | static_analysis | path=mcp-invest/server.py, symbol=fin\_instrument\_prices\_get, lines=\[326, 334\], declaration=fin\_instrument\_prices\… |  |
| `E-f4683001bb` | source_code | static_analysis | path=mcp-invest/server.py, symbol=ideas\_list, lines=\[338, 343\], declaration=ideas\_list |  |
| `E-ae129c839f` | source_code | static_analysis | path=app/agent/tools.py, symbol=duckduckgo\_search, lines=\[19, 46\], declaration=duckduckgo\_search |  |
| `E-a8e84c5556` | policy_snapshot | policy_inspection | path=examples/genai\_invest\_stand.policy.json, policy\_id=genai-invest-stand-expected, version=1.0.0 | declared expectations; not evidence of enforcement |
| `E-accb7535b7` | deployment_snapshot | parsing | path=examples/genai\_invest\_stand.deployment.json, service=redis | bind/publication only; reachability per network zone not established |
| `E-13933d746a` | deployment_snapshot | parsing | path=examples/genai\_invest\_stand.deployment.json, service=mongo | bind/publication only; reachability per network zone not established |
| `E-3e583f024d` | deployment_snapshot | parsing | path=examples/genai\_invest\_stand.deployment.json, service=postgres | bind/publication only; reachability per network zone not established |
| `E-621f3b4a0a` | deployment_snapshot | parsing | path=examples/genai\_invest\_stand.deployment.json, service=invest-server | bind/publication only; reachability per network zone not established |
| `E-3e749d36e7` | deployment_snapshot | parsing | path=examples/genai\_invest\_stand.deployment.json, service=mcp-invest | bind/publication only; reachability per network zone not established |
| `E-47d34eedef` | deployment_snapshot | parsing | path=examples/genai\_invest\_stand.deployment.json, service=keycloak | bind/publication only; reachability per network zone not established |
| `E-7a4e1cb96b` | deployment_snapshot | parsing | path=examples/genai\_invest\_stand.deployment.json, service=agent-api | bind/publication only; reachability per network zone not established |
| `E-0ea4670b1a` | deployment_snapshot | parsing | path=examples/genai\_invest\_stand.deployment.json, service=librechat | bind/publication only; reachability per network zone not established |
| `E-7f77a9072e` | deployment_snapshot | parsing | path=examples/genai\_invest\_stand.deployment.json, service=oauth2-proxy | bind/publication only; reachability per network zone not established |
| `E-9cccb65e85` | definition | parsing | server=mcp-invest, tool=instruments\_search, inventory=config | definition text is untrusted self-report |
| `E-570d9592d1` | definition | parsing | server=mcp-invest, tool=portfolio\_get\_positions\_valuation, inventory=config | definition text is untrusted self-report |
| `E-a6d12ed718` | definition | parsing | server=mcp-invest, tool=portfolio\_presence\_get, inventory=config | definition text is untrusted self-report |
| `E-00248b4b5a` | definition | parsing | server=mcp-invest, tool=register\_tax\_get, inventory=config | definition text is untrusted self-report |
| `E-8a759338b9` | definition | parsing | server=mcp-invest, tool=client\_operation\_history\_list, inventory=config | definition text is untrusted self-report |
| `E-d9ec683108` | definition | parsing | server=mcp-invest, tool=client\_training\_list, inventory=config | definition text is untrusted self-report |
| `E-5fd1937860` | definition | parsing | server=mcp-invest, tool=margin\_instruments\_list, inventory=config | definition text is untrusted self-report |
| `E-c6355e2f0f` | definition | parsing | server=mcp-invest, tool=fin\_instrument\_prices\_get, inventory=config | definition text is untrusted self-report |
| `E-a4c6024833` | definition | parsing | server=mcp-invest, tool=ideas\_list, inventory=config | definition text is untrusted self-report |
| `E-f9d7771d4d` | definition | parsing | server=agent-native, tool=duckduckgo\_search, inventory=config | definition text is untrusted self-report |

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
