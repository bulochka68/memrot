"""Эмуляция invest-alfadirect-mcp-server: MCP-сервер с read-тулами по инвестиционному профилю клиента.

Каждый вызов требует валидный Bearer-токен Keycloak (проверяется через `auth.py`).
Два режима (`MCP_INVEST_AUTH_MODE`):

- vulnerable (по умолчанию) — любой валидный токен (в т.ч. токен технической УЗ
  агента, ничем не ограниченный) даёт доступ к данным ЛЮБОГО клиента. Это осознанная
  BAC-уязвимость: авторизация фактически делегирована LLM, а не IAM.
- protected — чувствительные тулы требуют, чтобы токен нёс claim `cus`, полученный
  через OAuth2 Token Exchange от имени конкретного пользователя, и совпадал с
  запрошенным cus/account_id.
"""

from mcp.server.fastmcp import Context, FastMCP

import auth
import data
import invest_client

mcp = FastMCP("mcp-invest", host="0.0.0.0", port=8000)


def _raw_auth_header(ctx: Context) -> str | None:
    request = ctx.request_context.request
    return request.headers.get("authorization") if request is not None else None


def _authenticate(ctx: Context) -> tuple[dict | None, dict | None]:
    """Достать и провалидировать токен из запроса. Возвращает (claims, error)."""
    try:
        claims = auth.validate_token(_raw_auth_header(ctx))
    except auth.AuthError as exc:
        return None, {"error": str(exc)}
    return claims, None


def _demo_mode(ctx: Context) -> str | None:
    """Режим (vulnerable/protected), выбранный в UI стенда для этого запроса, если есть."""
    request = ctx.request_context.request
    return request.headers.get("x-demo-auth-mode") if request is not None else None


def _effective_mode(ctx: Context) -> str:
    return _demo_mode(ctx) or auth.AUTH_MODE


def _invest_server_error(exc: invest_client.InvestServerError) -> dict:
    return {"error": str(exc)}


def _check_cus(claims: dict, cus: str, ctx: Context) -> dict | None:
    try:
        auth.check_cus_access(claims, cus, mode=_demo_mode(ctx))
    except auth.AuthError as exc:
        return {"error": str(exc)}
    return None


@mcp.tool()
def instruments_search(query: str, ctx: Context) -> list[dict] | dict:
    """Поиск финансовых инструментов по тикеру, ISIN или названию компании.

    Используй этот тул первым, если известен только тикер/название, а не ISIN —
    большинству остальных тулов нужен именно ISIN.
    """
    _, err = _authenticate(ctx)
    if err:
        return err
    q = query.strip().lower()
    results = []
    for inst in data.INSTRUMENTS:
        if q in inst["isin"].lower() or q in inst["ticker"].lower() or q in inst["name"].lower():
            results.append({
                "isin": inst["isin"], "ticker": inst["ticker"], "name": inst["name"],
                "type": inst["type"], "market": inst["market"],
            })
    return results


@mcp.tool()
def portfolio_get_positions_valuation(cus: str, ctx: Context) -> dict:
    """Получить состав и стоимость инвестиционного портфеля клиента по CUS.

    Возвращает деньги и бумаги по всем брокерским счетам клиента. cus — идентификатор
    клиента (например, значение из поля user_id текущего чата или любое другое, которое
    назовёт пользователь).
    """
    claims, err = _authenticate(ctx)
    if err:
        return err
    if err := _check_cus(claims, cus, ctx):
        return err

    mode = _effective_mode(ctx)
    try:
        client = invest_client.get_client(cus, _raw_auth_header(ctx), mode)
    except invest_client.InvestServerError as exc:
        return _invest_server_error(exc)

    accounts_out = []
    total_rub = 0.0
    for acc in client["accounts"]:
        stocks = []
        stocks_sum = 0.0
        for pos in acc["positions"]:
            inst = data.get_instrument(pos["isin"])
            if not inst:
                continue
            amount_rub = round(inst["price"] * pos["amount"], 2)
            stocks_sum += amount_rub
            stocks.append({
                "isin": inst["isin"], "ticker": inst["ticker"], "name": inst["name"],
                "amount": pos["amount"], "price": inst["price"], "amount_rub": amount_rub,
            })
        account_total = round(acc["cash_rub"] + stocks_sum, 2)
        total_rub += account_total
        accounts_out.append({
            "account_id": acc["account_id"],
            "available_cash_rub": acc["cash_rub"],
            "total_value_rub": account_total,
            "stocks": stocks,
        })

    return {
        "cus": cus,
        "client_name": client["name"],
        "portfolio_total_rub": round(total_rub, 2),
        "broker": {"accounts": accounts_out},
    }


@mcp.tool()
def portfolio_presence_get(cus: str, ctx: Context) -> dict:
    """Проверить наличие брокерского счёта у клиента и общую стоимость портфеля в рублях."""
    claims, err = _authenticate(ctx)
    if err:
        return err
    if err := _check_cus(claims, cus, ctx):
        return err

    mode = _effective_mode(ctx)
    try:
        client = invest_client.get_client(cus, _raw_auth_header(ctx), mode)
    except invest_client.InvestServerError as exc:
        return _invest_server_error(exc)

    total = 0.0
    for acc in client["accounts"]:
        stocks_sum = sum(
            (data.get_instrument(p["isin"]) or {}).get("price", 0) * p["amount"]
            for p in acc["positions"]
        )
        total += acc["cash_rub"] + stocks_sum
    return {"broker": True, "partners": False, "money_rub": round(total, 2)}


@mcp.tool()
def register_tax_get(cus: str, account_id: str, year: int, ctx: Context) -> dict:
    """Получить налоговую информацию по брокерскому счёту клиента за указанный год.

    cus и account_id должны относиться к одному и тому же клиенту.
    """
    claims, err = _authenticate(ctx)
    if err:
        return err
    if err := _check_cus(claims, cus, ctx):
        return err

    mode = _effective_mode(ctx)
    try:
        record = invest_client.get_tax(account_id, year, _raw_auth_header(ctx), mode)
    except invest_client.InvestServerError as exc:
        return _invest_server_error(exc)
    return {"cus": cus, "account_id": account_id, "year": year, **record}


@mcp.tool()
def client_operation_history_list(
    cus: str,
    account_id: str,
    ctx: Context,
    date_from: str | None = None,
    date_to: str | None = None,
    max_elements: int = 50,
) -> list[dict] | dict:
    """Получить историю операций по брокерскому счёту клиента (покупки, продажи, выплаты)."""
    claims, err = _authenticate(ctx)
    if err:
        return err
    if err := _check_cus(claims, cus, ctx):
        return err

    mode = _effective_mode(ctx)
    try:
        ops = invest_client.get_operations(account_id, _raw_auth_header(ctx), mode, date_from, date_to)
    except invest_client.InvestServerError as exc:
        return _invest_server_error(exc)
    return ops[:max_elements]


@mcp.tool()
def margin_instruments_list(account_id: str, ctx: Context) -> list[dict] | dict:
    """Получить список маржинальных инструментов, доступных по брокерскому счёту."""
    claims, err = _authenticate(ctx)
    if err:
        return err
    mode = _effective_mode(ctx)
    owner_cus = invest_client.get_account_owner(account_id, _raw_auth_header(ctx), mode) or account_id
    if err := _check_cus(claims, owner_cus, ctx):
        return err

    try:
        accounts = invest_client.get_client(owner_cus, _raw_auth_header(ctx), mode)["accounts"]
    except invest_client.InvestServerError:
        accounts = []
    account_positions = next((a["positions"] for a in accounts if a["account_id"] == account_id), [])
    isins = {p["isin"] for p in account_positions}
    isins |= set(data.MARGIN_INFO.keys())
    result = []
    for isin in isins:
        inst = data.get_instrument(isin)
        margin = data.MARGIN_INFO.get(isin)
        if not inst or not margin:
            continue
        result.append({
            "isin": isin, "ticker": inst["ticker"],
            "margin_available": margin["margin_available"], "short_available": margin["short_available"],
        })
    return result


@mcp.tool()
def margin_instrument_get_info(account_id: str, isin: str, ctx: Context) -> dict:
    """Получить ставки риска (long/short) для конкретного инструмента по брокерскому счёту."""
    claims, err = _authenticate(ctx)
    if err:
        return err
    mode = _effective_mode(ctx)
    owner_cus = invest_client.get_account_owner(account_id, _raw_auth_header(ctx), mode) or account_id
    if err := _check_cus(claims, owner_cus, ctx):
        return err

    inst = data.get_instrument(isin)
    margin = data.MARGIN_INFO.get(isin)
    if not inst or not margin:
        return {"error": f"Маржинальные параметры для {isin} не найдены"}
    return {"isin": isin, "ticker": inst["ticker"], "account_id": account_id, **margin}


@mcp.tool()
def client_training_list(cus: str, ctx: Context) -> list[dict] | dict:
    """Получить список обязательных тестов клиента и статус их прохождения (допуск к марже/сложным инструментам)."""
    claims, err = _authenticate(ctx)
    if err:
        return err
    if err := _check_cus(claims, cus, ctx):
        return err
    try:
        return invest_client.get_training(cus, _raw_auth_header(ctx), _effective_mode(ctx))
    except invest_client.InvestServerError as exc:
        return _invest_server_error(exc)


@mcp.tool()
def dividend_calendar_list(
    ctx: Context,
    isin: str | None = None,
    date_from: str | None = None,
    date_to: str | None = None,
) -> list[dict] | dict:
    """Календарь выплат по дивидендам. Без isin возвращает общий календарь по всем инструментам."""
    _, err = _authenticate(ctx)
    if err:
        return err

    events = data.DIVIDENDS
    if isin:
        events = [e for e in events if e["isin"] == isin]
    if date_from:
        events = [e for e in events if e["last_buy_date"] >= date_from]
    if date_to:
        events = [e for e in events if e["last_buy_date"] <= date_to]
    return sorted(events, key=lambda e: e["last_buy_date"])


@mcp.tool()
def coupon_calendar_list(isin: str, date_from: str, date_to: str, ctx: Context) -> list[dict] | dict:
    """Календарь прошедших и будущих купонных выплат по облигации. isin, date_from, date_to обязательны."""
    _, err = _authenticate(ctx)
    if err:
        return err
    schedule = data._coupon_schedule(isin)
    return [e for e in schedule if date_from <= e["date"] <= date_to]


@mcp.tool()
def bond_get_info(isin: str, ctx: Context) -> dict:
    """Описание облигации по ISIN: номинал, купон, доходность, дата погашения."""
    _, err = _authenticate(ctx)
    if err:
        return err
    inst = data.get_instrument(isin)
    if not inst or inst["type"] != "bond":
        return {"error": f"Облигация с isin={isin} не найдена"}
    emitent = data.EMITENTS.get(isin, {})
    return {
        "isin": isin, "name": inst["name"], "nominal": inst["nominal"], "price": inst["price"],
        "coupon_rate": inst["coupon_rate"], "maturity": inst["maturity"], "currency": inst["currency"],
        "rating": emitent.get("rating"),
    }


@mcp.tool()
def emitent_get_static_info(isin: str, ctx: Context) -> dict:
    """Статическая информация об эмитенте по ISIN: профиль компании, сектор, ключевые показатели."""
    _, err = _authenticate(ctx)
    if err:
        return err
    emitent = data.EMITENTS.get(isin)
    if not emitent:
        return {"error": f"Информация об эмитенте для {isin} не найдена"}
    return {"isin": isin, **emitent}


@mcp.tool()
def fin_instrument_prices_get(isin: str, ctx: Context) -> dict:
    """Получить текущую цену финансового инструмента по ISIN."""
    _, err = _authenticate(ctx)
    if err:
        return err
    inst = data.get_instrument(isin)
    if not inst:
        return {"error": f"Инструмент с isin={isin} не найден"}
    return {"isin": isin, "ticker": inst["ticker"], "price": inst["price"], "currency": inst["currency"]}


@mcp.tool()
def ideas_list(ctx: Context) -> list[dict] | dict:
    """Получить список актуальных торговых идей и рекомендаций (не привязаны к конкретному клиенту)."""
    _, err = _authenticate(ctx)
    if err:
        return err
    return data.IDEAS


if __name__ == "__main__":
    mcp.run(transport="streamable-http")
