"""invest-server: бэкенд на Postgres с клиентскими данными (счета, позиции, налоги,
операции, тестирования). Вызывается из mcp-invest, не напрямую агентом.

Два режима (INVEST_SERVER_AUTH_MODE, переопределяется заголовком X-Demo-Auth-Mode
на конкретный запрос — mcp-invest форвардит его вместе со своим тогглом UI):

- vulnerable (по умолчанию) — любой валидный токен даёт доступ к данным ЛЮБОГО
  клиента. В связке с mcp-invest это значит: технический токен mcp-invest-service
  (без claim cus) беспрепятственно проходит — это осознанная BAC-уязвимость на
  уровне сервис-к-сервису (см. auth.py:check_cus_access).
- protected — токен должен нести claim cus, полученный в конечном счёте от
  реального пользователя через OAuth2 Token Exchange, и совпадать с запрошенным cus.
"""

from fastapi import FastAPI, Header, HTTPException, Query

import auth
import db

app = FastAPI(title="invest-server")


def _authenticate(authorization: str | None) -> dict:
    try:
        return auth.validate_token(authorization)
    except auth.AuthError as exc:
        raise HTTPException(status_code=401, detail=str(exc)) from exc


def _check_access(claims: dict, cus: str, mode: str | None) -> None:
    try:
        auth.check_cus_access(claims, cus, mode=mode)
    except auth.AuthError as exc:
        raise HTTPException(status_code=403, detail=str(exc)) from exc


@app.get("/healthz")
def healthz() -> dict:
    return {"status": "ok"}


@app.get("/clients/{cus}")
def get_client(
    cus: str,
    authorization: str | None = Header(default=None),
    x_demo_auth_mode: str | None = Header(default=None),
) -> dict:
    claims = _authenticate(authorization)
    _check_access(claims, cus, x_demo_auth_mode)
    client = db.get_client_with_accounts(cus)
    if not client:
        raise HTTPException(status_code=404, detail=f"Клиент с cus={cus} не найден")
    return client


@app.get("/accounts/{account_id}/owner")
def get_account_owner(
    account_id: str,
    authorization: str | None = Header(default=None),
) -> dict:
    # Только резолвит владельца счёта — не отдаёт клиентские данные, поэтому
    # достаточно валидного токена без cus-проверки (сама проверка происходит на
    # следующем вызове, когда caller уже знает cus и запрашивает конкретные данные).
    _authenticate(authorization)
    cus = db.get_account_owner(account_id)
    if not cus:
        raise HTTPException(status_code=404, detail=f"Счёт {account_id} не найден")
    return {"cus": cus}


@app.get("/accounts/{account_id}/tax/{year}")
def get_tax(
    account_id: str,
    year: int,
    authorization: str | None = Header(default=None),
    x_demo_auth_mode: str | None = Header(default=None),
) -> dict:
    claims = _authenticate(authorization)
    owner_cus = db.get_account_owner(account_id) or account_id
    _check_access(claims, owner_cus, x_demo_auth_mode)
    record = db.get_tax_record(account_id, year)
    if not record:
        raise HTTPException(status_code=404, detail=f"Налоговых данных за {year} год по счёту {account_id} не найдено")
    return record


@app.get("/accounts/{account_id}/operations")
def get_operations(
    account_id: str,
    authorization: str | None = Header(default=None),
    x_demo_auth_mode: str | None = Header(default=None),
    date_from: str | None = Query(default=None),
    date_to: str | None = Query(default=None),
) -> list[dict]:
    claims = _authenticate(authorization)
    owner_cus = db.get_account_owner(account_id) or account_id
    _check_access(claims, owner_cus, x_demo_auth_mode)
    return db.get_operations(account_id, date_from, date_to)


@app.get("/clients/{cus}/training")
def get_training(
    cus: str,
    authorization: str | None = Header(default=None),
    x_demo_auth_mode: str | None = Header(default=None),
) -> list[dict]:
    claims = _authenticate(authorization)
    _check_access(claims, cus, x_demo_auth_mode)
    return db.get_training(cus)
