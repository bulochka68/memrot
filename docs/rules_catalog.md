# Каталог контрольных требований (ruleset 2.0.0)

Сгенерировано командой `python -m mcp_audit rules --markdown`. Правила не содержат имён конкретного стенда: привязки живут в профилях.

| ID | Версия | Домен | Этап | Название | Требование | Критерий результата | Нужные источники (альтернативы) |
|---|---|---|---|---|---|---|---|
| MEM-01 | 2.0.0 | memory | B | Изоляция памяти согласно бизнес-политике | Личные записи доступны только разрешённой аудитории; разрешённое совместное использование продолжает работать. | Личные записи доступны только разрешённой аудитории; разрешённое совместное использование продолжает работать | source_snapshot / policy_snapshot+memory_event_snapshot / trace / control_fixtures |
| MEM-02 | 2.0.0 | memory | B | Разделение записи пользовательских данных и публикации общей политики | Сервис обработки пользовательской сессии не может публиковать общие правила; издатель имеет отдельное полномочие. | Сервис обработки пользовательской сессии не может публиковать общие правила; издатель имеет отдельное полномочие | source_snapshot / policy_snapshot+source_snapshot / memory_event_snapshot |
| MEM-03 | 2.0.0 | memory | B | Сервер определяет владельца и разрешённую область | Метаданные от LLM или внешнего содержимого не устанавливают полномочия записи. | Метаданные от LLM или внешнего содержимого не устанавливают полномочия записи | source_snapshot / memory_event_snapshot |
| MEM-04 | 2.0.0 | memory | B | Разделение данных и инструкций | Справочные записи не получают права менять общие правила из-за роли сообщения или пересказа. | Справочные записи не получают права менять общие правила из-за роли сообщения или пересказа | source_snapshot / trace |
| MEM-05 | 2.0.0 | memory | B | Сохранение происхождения при преобразовании | Производная запись связана со всеми известными родителями; потеря связи видима. | Производная запись связана со всеми известными родителями; потеря связи видима | source_snapshot / memory_event_snapshot |
| MEM-06 | 2.0.0 | memory | B | Отсутствие автоматического повышения доверия | Пересказ ассистентом и высокая LLM-confidence не являются разрешением публикации. | Пересказ ассистентом и высокая LLM-confidence не являются разрешением публикации | source_snapshot / memory_event_snapshot |
| MEM-07 | 2.0.0 | memory | B | Изоляция retrieval, кэша и индекса | Политика аудитории применяется до выдачи контекста; кэш не смешивает неразрешённые области. | Политика аудитории применяется до выдачи контекста; кэш не смешивает неразрешённые области | source_snapshot / memory_event_snapshot / trace |
| MEM-08 | 2.0.0 | memory | D | Отзыв производных данных | После отзыва источник и зависящие от него неприемлемые записи не возвращаются в контекст за пределами заданного срока. | После отзыва источник и зависящие от него неприемлемые записи не возвращаются в контекст за пределами заданного срока | memory_event_snapshot / control_fixtures / policy_snapshot |
| MEM-09 | 2.0.0 | memory | D | Корректность фоновых операций | Повторы, конкурирующие сессии и отложенные задачи сохраняют исходную идентичность и не публикуют отменённые данные. | Повторы, конкурирующие сессии и отложенные задачи сохраняют исходную идентичность и не публикуют отменённые данные | source_snapshot / trace |
| MEM-10 | 2.0.0 | memory | D | Управляемое хранение | TTL, ограничение объёма, обновление и очистка определены по типам памяти; старые записи не восстанавливаются неуправляемо. | TTL, ограничение объёма, обновление и очистка определены по типам памяти; старые записи не восстанавливаются неуправляемо | policy_snapshot+source_snapshot |
| AUTH-01 | 2.0.0 | identity | B | Доверенная входная идентичность | Пользователь устанавливается аутентификацией; произвольные поля тела и содержимое диалога её не заменяют. | Пользователь устанавливается аутентификацией; произвольные поля тела и содержимое диалога её не заменяют | source_snapshot / policy_snapshot+source_snapshot |
| AUTH-02 | 2.0.0 | identity | B | Авторизация субъекта на конкретный ресурс | На каждом сервисном переходе проверяется разрешение на объект, включая отношения клиент → счёт → операция. | На каждом сервисном переходе проверяется разрешение на объект, включая отношения клиент → счёт → операция | source_snapshot / control_fixtures / trace |
| AUTH-03 | 2.0.0 | identity | B | Серверная политика безопасности | Параметры клиента не ослабляют обязательные проверки защищённого deployment. | Параметры клиента не ослабляют обязательные проверки защищённого deployment | source_snapshot |
| AUTH-04 | 2.0.0 | identity | B | Проверка назначения и происхождения токена | Каждый принимающий сервис проверяет подходящие для своей схемы issuer, audience, подпись, время и требования к алгоритму. | Каждый принимающий сервис проверяет подходящие для своей схемы issuer, audience, подпись, время и требования к алгоритму | source_snapshot / policy_snapshot+source_snapshot |
| AUTH-05 | 2.0.0 | identity | B | Ограниченное делегирование | Передаваемые полномочия соответствуют задаче и ресурсу; сервисная учётная запись не обходит ограничения конечного пользователя. | Передаваемые полномочия соответствуют задаче и ресурсу; сервисная учётная запись не обходит ограничения конечного пользователя | source_snapshot |
| AUTH-06 | 2.0.0 | identity | D | Применение изменений полномочий | Смена роли, отзыв и окончание срока не оставляют действующий доступ через кэш или фоновую задачу сверх заданной политики. | Смена роли, отзыв и окончание срока не оставляют действующий доступ через кэш или фоновую задачу сверх заданной политики | source_snapshot / trace |
| INFRA-01 | 2.0.0 | infrastructure | B | Ограниченный доступ к памяти | Доступ к хранилищу имеют нужные сервисы с минимальными правами; публикация общей политики выделена отдельно. | Доступ к хранилищу имеют нужные сервисы с минимальными правами; публикация общей политики выделена отдельно | source_snapshot+policy_snapshot / deployment |
| INFRA-02 | 2.0.0 | infrastructure | B | Наблюдаемая сетевая граница | Отдельно описаны bind, публикация порта, маршрутизация и фильтрация; доступность подтверждается для конкретной зоны. | Отдельно описаны bind, публикация порта, маршрутизация и фильтрация; доступность подтверждается для конкретной зоны | deployment |
| INFRA-03 | 2.0.0 | infrastructure | B | Изоляция проверочного окружения | Проверки используют изолированные данные и ограниченные полномочия; флаг в конфиге не считается обеспечением изоляции. | Проверки используют изолированные данные и ограниченные полномочия; флаг в конфиге не считается обеспечением изоляции | control_fixtures |
| TOOL-01 | 2.0.0 | tools | B | Контроль одобренных определений | Определение связано с идентичностью сервера и согласованной версией; изменение даёт статус дрейфа. | Определение связано с идентичностью сервера и согласованной версией; изменение даёт статус дрейфа | mcp_inventory+baseline |
| TOOL-02 | 2.0.0 | tools | B | Корректный контракт операции | Входная/выходная схемы, обработка ошибок и реально наблюдаемая версия согласованы. | Входная/выходная схемы, обработка ошибок и реально наблюдаемая версия согласованы | mcp_inventory+source_snapshot / mcp_inventory / source_snapshot |
| TOOL-03 | 2.0.0 | tools | B | Однозначное разрешение имён | Namespace и выбор инструмента различают серверы; совпадение имён оценивается с учётом реального маршрутизатора. | Namespace и выбор инструмента различают серверы; совпадение имён оценивается с учётом реального маршрутизатора | mcp_inventory / source_snapshot |
| TOOL-04 | 2.0.0 | tools | B | Результат инструмента остаётся данными | Содержимое результата не управляет политикой доступа и издателем общей памяти. | Содержимое результата не управляет политикой доступа и издателем общей памяти | source_snapshot / trace |
| TOOL-05 | 2.0.0 | tools | B | Обоснованность текстовых сигналов | Linter сохраняет фрагмент, правило и объяснение; императив, Unicode или ссылка сами по себе не доказывают вредоносность. | Linter сохраняет фрагмент, правило и объяснение; императив, Unicode или ссылка сами по себе не доказывают вредоносность | mcp_inventory / source_snapshot |
| EGRESS-01 | 2.0.0 | egress | B | Контроль передаваемых данных | Для внешнего получателя разрешены и адресат, и категория данных; поиск учитывается как передача текста. | Для внешнего получателя разрешены и адресат, и категория данных; поиск учитывается как передача текста | source_snapshot+policy_snapshot / mcp_inventory |
| EGRESS-02 | 2.0.0 | egress | B | Наблюдаемость внешних эффектов | Разделяются подготовленный запрос, разрешение шлюза и фактически полученные локальной фикстурой данные. | Разделяются подготовленный запрос, разрешение шлюза и фактически полученные локальной фикстурой данные | control_fixtures |
| INV-01 | 2.0.0 | inventory | B | Согласованность инвентаря | configured / source_defined / live_advertised / runtime_observed / policy_authorized сопоставлены по ID сервера, сборке, роли и времени; расхождения объяснены. | Расхождение инвентаря имеет причину и не трактуется автоматически как скрытый инструмент | mcp_inventory+source_snapshot / mcp_inventory+policy_snapshot / mcp_inventory+trace / source_snapshot+policy_snapshot |
| INV-02 | 2.0.0 | inventory | B | Полнота и свежесть discovery | Отказ discovery виден как unavailable / partial / stale; config не подменяет успешный handshake. | Отказ discovery виден; config не подменяет успешный handshake | mcp_inventory |

## Подробности

### MEM-01 — Изоляция памяти согласно бизнес-политике

- Ожидаемый инвариант: retrieval of personal memory is bound to the requesting subject / allowed audience
- Допустимые методы: static_analysis, policy_inspection, observation, controlled_validation
- Критерий исправления: personal retrieval paths carry an audience filter; fixture read for a foreign subject is empty
- Приоритет по умолчанию: P0
- Известные ложные срабатывания: shared reference data explicitly allowed by policy; agents sharing memory by design
- Ограничения: scope/tenant fields in a document do not prove access control enforcement
- Внешние ориентиры: [OWASP ASI06 Memory & Context Poisoning](https://genai.owasp.org/2026/05/13/memory-is-a-feature-it-is-also-an-attack-surface/)

### MEM-02 — Разделение записи пользовательских данных и публикации общей политики

- Ожидаемый инвариант: no code path or service right lets user-session processing publish shared policy
- Допустимые методы: static_analysis, policy_inspection, observation
- Критерий исправления: user processing holds no publication permission for shared policy; the publisher is a distinct principal
- Приоритет по умолчанию: P0
- Известные ложные срабатывания: shared reference data published by a trusted process

### MEM-03 — Сервер определяет владельца и разрешённую область

- Ожидаемый инвариант: owner and audience are resolved server-side from the authenticated principal and policy
- Допустимые методы: static_analysis, observation
- Критерий исправления: proposed scope from a model or external content is advisory; the server decides
- Приоритет по умолчанию: P0

### MEM-04 — Разделение данных и инструкций

- Ожидаемый инвариант: context blocks carry an authority marking; data blocks are not presented as rules
- Допустимые методы: static_analysis, observation
- Критерий исправления: context assembly separates data from instructions and records each block's authority
- Приоритет по умолчанию: P0

### MEM-05 — Сохранение происхождения при преобразовании

- Ожидаемый инвариант: derived records reference their parents or are explicitly marked as lineage-lost
- Допустимые методы: static_analysis, policy_inspection
- Критерий исправления: every derived record carries parent references or an explicit lost-lineage mark
- Приоритет по умолчанию: P1

### MEM-06 — Отсутствие автоматического повышения доверия

- Ожидаемый инвариант: publication to a shared audience requires an authorized review/approval transition
- Допустимые методы: static_analysis, policy_inspection
- Критерий исправления: shared records carry an approved review state from a trusted publisher
- Приоритет по умолчанию: P0

### MEM-07 — Изоляция retrieval, кэша и индекса

- Ожидаемый инвариант: audience policy is applied before context delivery; caches and indexes are partitioned by audience
- Допустимые методы: static_analysis, observation
- Критерий исправления: retrieval, cache keys and index partitions include the audience
- Приоритет по умолчанию: P1
- Известные ложные срабатывания: similarity / top_k alone says nothing about rights

### MEM-08 — Отзыв производных данных

- Ожидаемый инвариант: revoked sources and their derivatives leave retrieval within the agreed delay
- Допустимые методы: observation, controlled_validation
- Критерий исправления: after revocation, source and dependents do not return to context beyond the agreed delay
- Приоритет по умолчанию: P2
- Ограничения: stage D: revocation fixtures and index-version tracking are on the roadmap

### MEM-09 — Корректность фоновых операций

- Ожидаемый инвариант: background processing keeps identity, idempotency and policy revision
- Допустимые методы: static_analysis, observation
- Критерий исправления: background jobs carry job/parent ids, idempotency keys and the policy revision
- Приоритет по умолчанию: P2
- Ограничения: stage D: runtime job events (job ids, parent ids) are on the roadmap

### MEM-10 — Управляемое хранение

- Ожидаемый инвариант: each memory type has a defined retention and a cleanup mechanism
- Допустимые методы: policy_inspection, static_analysis
- Критерий исправления: each memory type has retention in config and a cleanup mechanism
- Приоритет по умолчанию: P2
- Ограничения: stage D: maintenance events are on the roadmap

### AUTH-01 — Доверенная входная идентичность

- Ожидаемый инвариант: the principal comes from authentication only
- Допустимые методы: static_analysis, controlled_validation
- Критерий исправления: body fields / conversation cannot override the authenticated principal
- Приоритет по умолчанию: P0

### AUTH-02 — Авторизация субъекта на конкретный ресурс

- Ожидаемый инвариант: each receiving service authorizes the subject for the concrete object
- Допустимые методы: static_analysis, controlled_validation, observation
- Критерий исправления: each receiving service decides authorization for the concrete object
- Приоритет по умолчанию: P0
- Известные ложные срабатывания: a refusal for an invalid token is not an object-level authorization
- Ограничения: an entry-API refusal does not cover a backend the request never reached

### AUTH-03 — Серверная политика безопасности

- Ожидаемый инвариант: mandatory checks are fixed server-side
- Допустимые методы: static_analysis, controlled_validation
- Критерий исправления: the server defines mandatory checks; client parameters cannot relax them
- Приоритет по умолчанию: P0

### AUTH-04 — Проверка назначения и происхождения токена

- Ожидаемый инвариант: each receiving service validates the checks required by its scheme
- Допустимые методы: static_analysis
- Критерий исправления: each receiving service rejects foreign issuer/audience tokens
- Приоритет по умолчанию: P1
- Известные ложные срабатывания: absence of JWT is not a failure; equivalent scheme requirements apply
- Внешние ориентиры: [RFC 8725 §3.8-3.9 (issuer / audience validation)](https://www.rfc-editor.org/rfc/rfc8725.html); [MCP Authorization Security Considerations (2026-07-28)](https://modelcontextprotocol.io/specification/2026-07-28/basic/authorization/security-considerations) — reference binding of requirements, not a statement about the protocol version implemented by the target

### AUTH-05 — Ограниченное делегирование

- Ожидаемый инвариант: delegated credentials are bound to the end user, task and resource
- Допустимые методы: static_analysis, controlled_validation
- Критерий исправления: downstream calls carry the end-user binding
- Приоритет по умолчанию: P0
- Внешние ориентиры: [MCP Authorization Security Considerations (2026-07-28)](https://modelcontextprotocol.io/specification/2026-07-28/basic/authorization/security-considerations) — reference binding of requirements, not a statement about the protocol version implemented by the target

### AUTH-06 — Применение изменений полномочий

- Ожидаемый инвариант: revocation and expiry take effect within the policy window
- Допустимые методы: static_analysis, observation
- Критерий исправления: revocation and expiry are checked within the policy window
- Приоритет по умолчанию: P2
- Ограничения: stage D: revocation traces are on the roadmap

### INFRA-01 — Ограниченный доступ к памяти

- Ожидаемый инвариант: service rights on memory stores are minimal and publication is separated
- Допустимые методы: policy_inspection, static_analysis, parsing
- Критерий исправления: service rights match policy; publication is a separate credential
- Приоритет по умолчанию: P0

### INFRA-02 — Наблюдаемая сетевая граница

- Ожидаемый инвариант: storage ports are not published beyond the intended zone
- Допустимые методы: parsing, observation
- Критерий исправления: storage ports are not published; reachability is refused per zone
- Приоритет по умолчанию: P0
- Известные ложные срабатывания: a published port is not automatically reachable from the internet

### INFRA-03 — Изоляция проверочного окружения

- Ожидаемый инвариант: controlled validation runs on synthetic data with technical isolation attested by the fixture
- Допустимые методы: observation
- Критерий исправления: fixture attests data, network and permission isolation
- Приоритет по умолчанию: P1

### TOOL-01 — Контроль одобренных определений

- Ожидаемый инвариант: every definition matches an approved baseline entry
- Допустимые методы: parsing
- Критерий исправления: definitions match an approved baseline for this server identity/version
- Приоритет по умолчанию: P1
- Известные ложные срабатывания: a changed hash is drift, not proof of a rug pull

### TOOL-02 — Корректный контракт операции

- Ожидаемый инвариант: configured, source-defined and live contracts agree
- Допустимые методы: static_analysis
- Критерий исправления: configured, source-defined and live schemas agree for each tool
- Приоритет по умолчанию: P1

### TOOL-03 — Однозначное разрешение имён

- Ожидаемый инвариант: tool names resolve unambiguously in the real router
- Допустимые методы: static_analysis
- Критерий исправления: the router resolves qualified names; duplicates are refused
- Приоритет по умолчанию: P1
- Известные ложные срабатывания: same names under a qualified namespace

### TOOL-04 — Результат инструмента остаётся данными

- Ожидаемый инвариант: tool results never reach policy publication without an authorized process
- Допустимые методы: static_analysis, observation
- Критерий исправления: no derivation path from tool results to shared policy without authorized review
- Приоритет по умолчанию: P0
- Внешние ориентиры: [MCP specification, Security and Trust & Safety](https://modelcontextprotocol.io/specification/2025-11-25) — annotations describe behaviour but do not enforce it

### TOOL-05 — Обоснованность текстовых сигналов

- Ожидаемый инвариант: definitions and context carry no unreviewed injection signals
- Допустимые методы: static_analysis
- Критерий исправления: every signal is reviewed; confirmed ones are fixed at the definition source
- Приоритет по умолчанию: P1
- Известные ложные срабатывания: legitimate imperatives in agent instruction files; technical Latin tokens in Cyrillic prose
- Ограничения: text heuristics produce hypotheses; they do not confirm compromise
- Внешние ориентиры: [MCP specification, Security and Trust & Safety](https://modelcontextprotocol.io/specification/2025-11-25) — annotations describe behaviour but do not enforce it

### EGRESS-01 — Контроль передаваемых данных

- Ожидаемый инвариант: both destination and data category are allowed for every external transmission
- Допустимые методы: static_analysis, policy_inspection
- Критерий исправления: egress policy enforced for destination and category
- Приоритет по умолчанию: P1
- Известные ложные срабатывания: an allowed search provider may still receive data it must not

### EGRESS-02 — Наблюдаемость внешних эффектов

- Ожидаемый инвариант: external effects are observed by a local fixture, not inferred from config text
- Допустимые методы: controlled_validation
- Критерий исправления: local fixture observes the actual payload
- Приоритет по умолчанию: P1
- Известные ложные срабатывания: the text 'sinkhole' in a config does not prove traffic redirection

### INV-01 — Согласованность инвентаря

- Ожидаемый инвариант: inventory sources agree or differences are explained
- Допустимые методы: static_analysis
- Критерий исправления: sources agree for the same identity/build/role/time or differences are explained
- Приоритет по умолчанию: P1
- Известные ложные срабатывания: feature flags, roles, another build, lazy attachment

### INV-02 — Полнота и свежесть discovery

- Ожидаемый инвариант: discovery is complete and fresh for the identity used
- Допустимые методы: observation
- Критерий исправления: handshake complete for the identity and time of the snapshot
- Приоритет по умолчанию: P2

