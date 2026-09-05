"""Исходящий клиент mcp-invest → invest-server.

Второй, независимый хоп той же BAC-демонстрации: в уязвимом режиме mcp-invest
ходит на invest-server собственной нерестрицированной технической УЗ
(mcp-invest-service, без claim cus) — invest-server, работая в том же режиме,
доверяет этому токену вслепую. В защищённом режиме mcp-invest вместо этого
форвардит дальше as-is тот cus-ограниченный токен, что сам получил от агента.
"""

import os
import time
from typing import Any

import httpx

INVEST_SERVER_URL = os.environ.get("INVEST_SERVER_URL", "http://invest-server:8000")
KEYCLOAK_URL = os.environ.get("KEYCLOAK_URL", "http://keycloak:8080")
KEYCLOAK_REALM = os.environ.get("KEYCLOAK_REALM", "genai-stand")
SERVICE_CLIENT_ID = os.environ.get("MCP_INVEST_SERVICE_CLIENT_ID", "mcp-invest-service")
SERVICE_CLIENT_SECRET = os.environ.get("MCP_INVEST_SERVICE_CLIENT_SECRET", "mcp-invest-service-secret")

_TOKEN_ENDPOINT = f"{KEYCLOAK_URL.rstrip('/')}/realms/{KEYCLOAK_REALM}/protocol/openid-connect/token"

_service_token_cache: dict[str, Any] = {}


class InvestServerError(Exception):
    """invest-server вернул ошибку (401/403/404/5xx) или недоступен."""


def _get_service_token() -> str:
    """Токен технической УЗ mcp-invest-service (client_credentials), с кэшем до истечения."""
    cached = _service_token_cache.get("token")
    if cached and _service_token_cache.get("expires_at", 0) > time.time() + 10:
        return cached
    resp = httpx.post(_TOKEN_ENDPOINT, data={
        "grant_type": "client_credentials",
        "client_id": SERVICE_CLIENT_ID,
        "client_secret": SERVICE_CLIENT_SECRET,
    }, timeout=10)
    resp.raise_for_status()
    data = resp.json()
    _service_token_cache["token"] = data["access_token"]
    _service_token_cache["expires_at"] = time.time() + data.get("expires_in", 60)
    return data["access_token"]


def _outbound_headers(incoming_authorization: str | None, mode: str) -> dict[str, str]:
    if mode == "protected" and incoming_authorization:
        token_header = incoming_authorization
    else:
        token_header = f"Bearer {_get_service_token()}"
    return {"Authorization": token_header, "X-Demo-Auth-Mode": mode}


def _request(method: str, path: str, incoming_authorization: str | None, mode: str, **kwargs) -> Any:
    headers = _outbound_headers(incoming_authorization, mode)
    try:
        resp = httpx.request(method, f"{INVEST_SERVER_URL.rstrip('/')}{path}", headers=headers, timeout=10, **kwargs)
    except httpx.HTTPError as exc:
        raise InvestServerError(f"invest-server недоступен: {exc}") from exc
    if resp.status_code >= 400:
        try:
            detail = resp.json().get("detail", resp.text)
        except ValueError:
            detail = resp.text
        raise InvestServerError(detail)
    return resp.json()


def get_client(cus: str, incoming_authorization: str | None, mode: str) -> dict:
    return _request("GET", f"/clients/{cus}", incoming_authorization, mode)


def get_account_owner(account_id: str, incoming_authorization: str | None, mode: str) -> str | None:
    try:
        return _request("GET", f"/accounts/{account_id}/owner", incoming_authorization, mode)["cus"]
    except InvestServerError:
        return None


def get_tax(account_id: str, year: int, incoming_authorization: str | None, mode: str) -> dict:
    return _request("GET", f"/accounts/{account_id}/tax/{year}", incoming_authorization, mode)


def get_operations(
    account_id: str, incoming_authorization: str | None, mode: str,
    date_from: str | None = None, date_to: str | None = None,
) -> list[dict]:
    params = {k: v for k, v in {"date_from": date_from, "date_to": date_to}.items() if v}
    return _request("GET", f"/accounts/{account_id}/operations", incoming_authorization, mode, params=params)


def get_training(cus: str, incoming_authorization: str | None, mode: str) -> list[dict]:
    return _request("GET", f"/clients/{cus}/training", incoming_authorization, mode)
