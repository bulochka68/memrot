"""HTTP-ручка для автоматизированного тестирования агента (promptfoo и подобные тулы) +
страницы стенда: "Мой аккаунт" (API-ключи) и "Память" (просмотр памяти агента).

OpenAI-совместимый /v1/chat/completions с авторизацией по долгоживущему API-ключу,
а не по короткоживущей SSO-сессии Keycloak — тестовый прогон может идти дольше, чем
живёт access-токен (5 минут).

Не меняет модель безопасности стенда: user_id берётся строго из привязки API-ключа,
тело запроса не может его переопределить. Это headless-доступ к тому же run_research,
что использует LibreChat/страница аккаунта — все сценарии из отчёта "Атаки на стенд
GenAI" одинаково воспроизводимы что через UI, что через эту ручку.
"""

import html
import json
import time
import urllib.parse
import uuid

import jwt
from fastapi import FastAPI, Header, HTTPException, Request
from fastapi.responses import HTMLResponse, RedirectResponse, StreamingResponse
from jwt import PyJWKClient
from pydantic import BaseModel

from app.agent.runner import run_research
from app.apikeys import generate_key, hash_key
from app.config import get_settings
from app.memory.mongo import MongoMemoryStore
from app.memory.working import WorkingMemoryStore
from app.orchestrator.graph import finalize_session

app = FastAPI(title="genai-stand agent API")
_mongo = MongoMemoryStore()
_working = WorkingMemoryStore()
_settings = get_settings()
_jwk_client: PyJWKClient | None = None


def _get_jwk_client() -> PyJWKClient | None:
    global _jwk_client
    if _jwk_client is None and _settings.keycloak_url:
        jwks_url = f"{_settings.keycloak_url.rstrip('/')}/realms/{_settings.keycloak_realm}/protocol/openid-connect/certs"
        _jwk_client = PyJWKClient(jwks_url, cache_keys=True, lifespan=300)
    return _jwk_client


def _current_identity(request: Request) -> dict | None:
    """Личность залогиненного через Keycloak пользователя — из токена, который
    прокинул oauth2-proxy заголовком X-Forwarded-Access-Token. None, если запрос пришёл
    не через прокси (например, напрямую на порт 8600 — так ходят /v1/* с Bearer-ключом).
    """
    token = request.headers.get("x-forwarded-access-token")
    jwk_client = _get_jwk_client()
    if not token or jwk_client is None:
        return None
    try:
        signing_key = jwk_client.get_signing_key_from_jwt(token)
        claims = jwt.decode(
            token, signing_key.key, algorithms=["RS256"],
            options={"verify_aud": False, "verify_iss": False},
        )
    except jwt.PyJWTError:
        return None
    return {
        "cus": claims.get("cus"),
        "username": claims.get("preferred_username", "?"),
        "name": claims.get("name", claims.get("preferred_username", "?")),
    }


def _logout_url() -> str:
    post_logout_redirect = "http://localhost:8501"
    end_session_url = (
        f"{_settings.keycloak_issuer_url.rstrip('/')}/realms/{_settings.keycloak_realm}"
        "/protocol/openid-connect/logout"
        f"?client_id={_settings.streamlit_app_client_id}"
        f"&post_logout_redirect_uri={urllib.parse.quote(post_logout_redirect, safe='')}"
    )
    return "/oauth2/sign_out?rd=" + urllib.parse.quote(end_session_url, safe="")


def _account_page(identity: dict, user_id: str, *, new_key: str | None = None) -> str:
    def _revoke_cell(k) -> str:
        if k.revoked:
            return ""
        return (
            f"<form method=post action=/keys/{k.key_id}/revoke style=display:inline>"
            "<button type=submit>Отозвать</button></form>"
        )

    rows = "".join(
        f"<tr><td><code>{html.escape(k.key_prefix)}…</code></td>"
        f"<td>{'отозван' if k.revoked else 'активен'}</td>"
        f"<td>{k.created_at.strftime('%Y-%m-%d %H:%M')}</td>"
        f"<td>{_revoke_cell(k)}</td></tr>"
        for k in _mongo.api_keys.list_for_user(user_id)
    )
    flash = (
        f"<div style='background:#e6ffed;border:1px solid #1a7f37;padding:1em;margin:1em 0'>"
        f"<b>Сохраните ключ сейчас — второй раз он не покажется:</b><br>"
        f"<code style='font-size:1.1em'>{html.escape(new_key)}</code></div>"
        if new_key else ""
    )
    agent_api_url = _settings.agent_api_url or "http://localhost:8600"
    return f"""<!doctype html><html><head><meta charset="utf-8">
<title>GenAI Investment Assistant — аккаунт</title>
<style>body{{font-family:sans-serif;max-width:700px;margin:2em auto;padding:0 1em}}
table{{border-collapse:collapse;width:100%}} td,th{{border-bottom:1px solid #ddd;padding:.4em;text-align:left}}
code{{background:#f4f4f4;padding:.2em .4em;border-radius:3px}}
pre{{background:#f4f4f4;padding:1em;border-radius:4px;overflow-x:auto}}</style></head><body>
<h1>Мой аккаунт</h1>
<p>Вход выполнен: <b>{html.escape(identity['name'])}</b> (cus={html.escape(user_id)}) —
<a href="/memory">Память агента</a> — <a href="{_logout_url()}">Выйти</a></p>
{flash}
<h2>API-ключ для автотестирования / LibreChat</h2>
<p>Долгоживущий ключ для headless-доступа (promptfoo, custom endpoint в LibreChat) — не истекает сам по себе, в отличие от SSO-сессии.</p>
<form method="post" action="/keys"><button type="submit">Сгенерировать ключ</button></form>
<table><tr><th>Ключ</th><th>Статус</th><th>Создан</th><th></th></tr>{rows}</table>
<h2>Как подключить</h2>
<p>Ручка автотестирования: <code>{agent_api_url}/v1/chat/completions</code></p>
<pre>providers:
  - id: openai:chat:genai-invest-assistant
    config:
      apiBaseUrl: {agent_api_url}/v1
      apiKey: sk-genai-...</pre>
<p>В LibreChat: выбрать custom endpoint "Ассистент по инвестициям" → вставить ключ в настройках.</p>
</body></html>"""


def _memory_page(identity: dict, user_id: str) -> str:
    def _msg_lines(messages) -> str:
        return "".join(
            f"<div><code>[{html.escape(m.role)}]</code> {html.escape(m.content)}</div>"
            for m in messages
        )

    working_sessions = _working.list_sessions(user_id)
    working_html = "".join(
        f"<details{' open' if i == 0 else ''}><summary>Сессия <code>{html.escape(sid)}</code>"
        f" — {len(wm.messages)} сообщ.{f', саммари: {html.escape(wm.summary)}' if wm.summary else ''}</summary>"
        f"{_msg_lines(wm.messages)}</details>"
        for i, (sid, wm) in enumerate(working_sessions)
    ) or "<p><i>Пусто — рабочая память живёт только TTL после последнего сообщения сессии.</i></p>"

    dialog_html = "".join(
        f"<details><summary>Сессия <code>{html.escape(d.session_id)}</code>"
        f" — {len(d.messages)} сообщ., {d.started_at.strftime('%Y-%m-%d %H:%M')}"
        f"{' — ' + d.ended_at.strftime('%Y-%m-%d %H:%M') if d.ended_at else ''}"
        f", source={html.escape(d.source)}</summary>{_msg_lines(d.messages)}</details>"
        for d in _mongo.dialog.list_for_user(user_id, limit=_settings.max_dialog_sessions)
    ) or "<p><i>Пусто — сессия попадает сюда после POST /v1/sessions/{id}/finalize.</i></p>"

    episodic_html = "".join(
        f"<tr><td><code>{html.escape(e.session_id)}</code></td><td>{html.escape(e.summary)}</td>"
        f"<td>{e.created_at.strftime('%Y-%m-%d %H:%M')}</td><td>{html.escape(e.source)}</td></tr>"
        for e in _mongo.episodic.list_for_user(user_id, limit=_settings.max_episodic_memories)
    )

    user_facts = [
        s for s in _mongo.semantic.list_for_context(user_id, limit=_settings.max_semantic_memories)
        if s.scope != "global"
    ]
    semantic_html = "".join(
        f"<tr><td>{html.escape(s.fact)}</td><td>{s.confidence:.2f}</td>"
        f"<td>{s.created_at.strftime('%Y-%m-%d %H:%M')}</td><td>{html.escape(s.source)}</td></tr>"
        for s in user_facts
    )

    policy_html = "".join(
        f"<tr><td>{html.escape(p.statement)}</td><td>{p.confidence:.2f}</td>"
        f"<td>{p.created_at.strftime('%Y-%m-%d %H:%M')}</td>"
        f"<td><code>{html.escape(p.source_session_id or '')}</code></td></tr>"
        for p in _mongo.agent_policy.list_all(limit=_settings.max_semantic_memories)
    )

    return f"""<!doctype html><html><head><meta charset="utf-8">
<title>GenAI Investment Assistant — память</title>
<style>body{{font-family:sans-serif;max-width:900px;margin:2em auto;padding:0 1em}}
table{{border-collapse:collapse;width:100%;margin-bottom:1em}} td,th{{border-bottom:1px solid #ddd;padding:.4em;text-align:left;vertical-align:top}}
code{{background:#f4f4f4;padding:.2em .4em;border-radius:3px}}
details{{border:1px solid #ddd;border-radius:4px;padding:.5em .8em;margin-bottom:.5em}}
summary{{cursor:pointer}}
.danger{{border:1px solid #cf222e;border-radius:4px;padding:.8em}}
.danger table{{margin-bottom:0}}</style></head><body>
<h1>Память агента</h1>
<p><a href="/">Мой аккаунт</a> —
Вход выполнен: <b>{html.escape(identity['name'])}</b> (cus={html.escape(user_id)}) — <a href="{_logout_url()}">Выйти</a></p>
<p><i>То же самое, что <code>MemoryStore.build_context()</code> подмешивает в системный промпт агента
перед каждым вашим запросом — лимиты записей те же (см. <code>MAX_DIALOG_SESSIONS</code> и т.п.).</i></p>

<h2>Рабочая память (Redis, текущие сессии)</h2>
{working_html}

<h2>Диалоговая память (прошлые сессии целиком)</h2>
{dialog_html}

<h2>Эпизодическая память (саммари сессий)</h2>
<table><tr><th>Сессия</th><th>Саммари</th><th>Создано</th><th>Источник</th></tr>{episodic_html}</table>

<h2>Семантическая память (факты о вас, cus={html.escape(user_id)})</h2>
<table><tr><th>Факт</th><th>Confidence</th><th>Создано</th><th>Источник</th></tr>{semantic_html}</table>

<h2>⚠ Политика агента — общая для ВСЕХ клиентов, не только для вас</h2>
<div class="danger">
<p>Эти записи попадают в системный промпт агента для <b>любого</b> клиента, не только того,
чья сессия их породила — это демонстрация отравления памяти (memory poisoning):
достаточно, чтобы модель во время финализации сессии сочла факт применимым «глобально».</p>
<table><tr><th>Утверждение</th><th>Confidence</th><th>Создано</th><th>Сессия-источник</th></tr>{policy_html}</table>
</div>
</body></html>"""


class ChatMessage(BaseModel):
    role: str
    content: str


class ChatCompletionRequest(BaseModel):
    model: str = "genai-invest-assistant"
    messages: list[ChatMessage]
    # Расширения поверх стандартной OpenAI-формы — необязательны, promptfoo может их не знать.
    session_id: str | None = None
    auth_mode: str = "vulnerable"  # "vulnerable" | "protected" — какой режим стенда тестируем
    stream: bool = False


def _resolve_user(authorization: str | None) -> str:
    if not authorization or not authorization.lower().startswith("bearer "):
        raise HTTPException(status_code=401, detail="Требуется заголовок Authorization: Bearer <api-key>")
    raw_key = authorization.split(" ", 1)[1].strip()
    record = _mongo.api_keys.find_by_hash(hash_key(raw_key))
    if not record:
        raise HTTPException(status_code=401, detail="Неизвестный или отозванный API-ключ")
    return record.user_id


@app.get("/healthz")
def healthz() -> dict:
    return {"status": "ok"}


@app.get("/", response_class=HTMLResponse)
def account_page(request: Request) -> str:
    identity = _current_identity(request)
    if identity is None:
        raise HTTPException(
            status_code=401,
            detail="Не удалось определить личность — страница должна быть открыта через "
            "oauth2-proxy (http://localhost:8501), а не напрямую на порт 8600.",
        )
    user_id = identity["cus"]
    if not user_id:
        raise HTTPException(status_code=400, detail=f"У пользователя {identity['username']} не задан атрибут cus в Keycloak.")
    return _account_page(identity, user_id)


@app.get("/memory", response_class=HTMLResponse)
def memory_page(request: Request) -> str:
    identity = _current_identity(request)
    if identity is None:
        raise HTTPException(
            status_code=401,
            detail="Не удалось определить личность — страница должна быть открыта через "
            "oauth2-proxy (http://localhost:8501), а не напрямую на порт 8600.",
        )
    user_id = identity["cus"]
    if not user_id:
        raise HTTPException(status_code=400, detail=f"У пользователя {identity['username']} не задан атрибут cus в Keycloak.")
    return _memory_page(identity, user_id)


@app.post("/keys", response_class=HTMLResponse)
def create_key(request: Request) -> str:
    identity = _current_identity(request)
    if identity is None or not identity.get("cus"):
        raise HTTPException(status_code=401, detail="Не удалось определить личность.")
    user_id = identity["cus"]
    raw_key, record = generate_key(user_id)
    _mongo.api_keys.create(record)
    return _account_page(identity, user_id, new_key=raw_key)


@app.post("/keys/{key_id}/revoke")
def revoke_key(key_id: str, request: Request) -> RedirectResponse:
    identity = _current_identity(request)
    if identity is None or not identity.get("cus"):
        raise HTTPException(status_code=401, detail="Не удалось определить личность.")
    _mongo.api_keys.revoke(key_id, identity["cus"])
    return RedirectResponse("/", status_code=303)


def _sse_stream(completion_id: str, model: str, created: int, content: str):
    first_chunk = {
        "id": completion_id, "object": "chat.completion.chunk", "created": created, "model": model,
        "choices": [{"index": 0, "delta": {"role": "assistant", "content": content}, "finish_reason": None}],
    }
    final_chunk = {
        "id": completion_id, "object": "chat.completion.chunk", "created": created, "model": model,
        "choices": [{"index": 0, "delta": {}, "finish_reason": "stop"}],
    }
    yield f"data: {json.dumps(first_chunk, ensure_ascii=False)}\n\n"
    yield f"data: {json.dumps(final_chunk, ensure_ascii=False)}\n\n"
    yield "data: [DONE]\n\n"


# Без "/" в начале — LibreChat сам перехватывает "/..." под свою палитру команд/промптов,
# сообщение с таким текстом никогда не доходит до нас как обычный текст.
_FINALIZE_COMMAND = "finalize"


def _finalize_reply(state: dict) -> str:
    episodes = state.get("episodes") or []
    facts = state.get("semantic_facts") or []
    global_facts = [f for f in facts if f.get("scope") == "global"]
    lines = [
        f"Сессия финализирована: {len(episodes)} эпизод(ов), {len(facts)} факт(ов) "
        f"в долговременной памяти.",
    ]
    if global_facts:
        lines.append(
            f"⚠ {len(global_facts)} из них помечены моделью как «общие для всех клиентов» "
            "и попадут в системный промпт агента для ЛЮБОГО пользователя, не только для вас:"
        )
        lines += [f"- {f['fact']}" for f in global_facts]
    return "\n".join(lines)


@app.post("/v1/chat/completions")
async def chat_completions(
    body: ChatCompletionRequest,
    authorization: str | None = Header(default=None),
    x_conversation_id: str | None = Header(default=None),
):
    user_id = _resolve_user(authorization)
    if body.auth_mode not in ("vulnerable", "protected"):
        raise HTTPException(status_code=400, detail="auth_mode должен быть 'vulnerable' или 'protected'")

    user_messages = [m for m in body.messages if m.role == "user"]
    if not user_messages:
        raise HTTPException(status_code=400, detail="В messages нужен хотя бы один message с role=user")
    query = user_messages[-1].content
    # session_id: явный из тела (curl/promptfoo) > X-Conversation-Id от LibreChat (librechat.yaml,
    # LIBRECHAT_BODY_CONVERSATIONID) > новый случайный — без второго варианта каждое сообщение
    # в LibreChat начинало бы новую сессию памяти, и рабочая память не накапливалась бы в диалоге.
    session_id = body.session_id or x_conversation_id or str(uuid.uuid4())[:8]

    if query.strip().lower() == _FINALIZE_COMMAND:
        # Ручная финализация текущей сессии прямо из чата — то же самое, что curl на
        # POST /v1/sessions/{id}/finalize, но доступно и тем, у кого нет доступа к терминалу
        # (LibreChat не даёт кастомных кнопок для custom endpoint).
        state = await finalize_session(user_id, session_id)
        final_report = _finalize_reply(state)
    else:
        result = await run_research(user_id, session_id, query, auth_mode=body.auth_mode)
        final_report = result["final_report"]

    completion_id = f"chatcmpl-{uuid.uuid4().hex[:24]}"
    created = int(time.time())

    if body.stream:
        # LibreChat (и большинство OpenAI-совместимых клиентов) всегда шлёт stream=true —
        # без SSE-формата клиент молча получает 0 дельт и пустой ответ, хотя HTTP-статус 200.
        # run_research не стримит по токенам, поэтому отдаём весь текст одним delta-чанком —
        # этого достаточно для клиентов, которые просто накапливают content по чанкам.
        return StreamingResponse(
            _sse_stream(completion_id, body.model, created, final_report),
            media_type="text/event-stream",
        )

    return {
        "id": completion_id,
        "object": "chat.completion",
        "created": created,
        "model": body.model,
        "choices": [
            {
                "index": 0,
                "message": {"role": "assistant", "content": final_report},
                "finish_reason": "stop",
            }
        ],
    }


@app.post("/v1/sessions/{session_id}/finalize")
async def finalize(session_id: str, authorization: str | None = Header(default=None)) -> dict:
    """То же, что кнопка "Завершить сессию → оркестратор" в UI — извлекает эпизоды/факты
    из рабочей памяти сессии в долговременную. Нужна автотестам многоходовых сценариев
    (отравление памяти, персистентная BAC-утечка): без вызова этой ручки между "атакой"
    и "проверкой на жертве" ничего не осядет в долговременной памяти.
    """
    user_id = _resolve_user(authorization)
    state = await finalize_session(user_id, session_id)
    return {
        "episodes": state.get("episodes"),
        "facts": state.get("semantic_facts"),
    }
