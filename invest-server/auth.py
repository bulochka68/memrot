"""Проверка Bearer-токенов Keycloak на входе в invest-server.

Тот же паттерн, что в mcp-invest/auth.py — общий пакет между разными Docker-образами
не оправдан, дублирование ~30 строк дешевле лишней зависимости.
"""

import os

import jwt
from jwt import PyJWKClient

KEYCLOAK_URL = os.environ.get("KEYCLOAK_URL", "http://keycloak:8080")
KEYCLOAK_REALM = os.environ.get("KEYCLOAK_REALM", "genai-stand")
# KC_HOSTNAME на Keycloak фиксирует claim `iss` отдельно от того, по какому адресу мы
# реально ходим за JWKS (внутренний docker-хост vs. видимый браузеру) — см. mcp-invest/auth.py.
KEYCLOAK_ISSUER_URL = os.environ.get("KEYCLOAK_ISSUER_URL", KEYCLOAK_URL)
ISSUER = f"{KEYCLOAK_ISSUER_URL}/realms/{KEYCLOAK_REALM}"
JWKS_URL = f"{KEYCLOAK_URL}/realms/{KEYCLOAK_REALM}/protocol/openid-connect/certs"
AUTH_MODE = os.environ.get("INVEST_SERVER_AUTH_MODE", "vulnerable")  # vulnerable | protected

_jwk_client: PyJWKClient | None = None


def _get_jwk_client() -> PyJWKClient:
    global _jwk_client
    if _jwk_client is None:
        _jwk_client = PyJWKClient(JWKS_URL, cache_keys=True, lifespan=300)
    return _jwk_client


class AuthError(Exception):
    """Токен отсутствует, невалиден или не проходит проверку доступа."""


def validate_token(authorization_header: str | None) -> dict:
    """Проверить Bearer-токен и вернуть его claims. Кидает AuthError, если что-то не так."""
    if not authorization_header or not authorization_header.lower().startswith("bearer "):
        raise AuthError("Отсутствует Bearer-токен в заголовке Authorization")
    token = authorization_header.split(" ", 1)[1].strip()

    try:
        signing_key = _get_jwk_client().get_signing_key_from_jwt(token)
        claims = jwt.decode(
            token,
            signing_key.key,
            algorithms=["RS256"],
            issuer=ISSUER,
            options={"verify_aud": False},
        )
    except jwt.PyJWTError as exc:
        raise AuthError(f"Невалидный токен: {exc}") from exc

    return claims


def check_cus_access(claims: dict, requested_cus: str, mode: str | None = None) -> None:
    """В защищённом режиме — убедиться, что токен ограничен именно этим cus.

    В уязвимом режиме — намеренно ничего не проверяет: сюда попадает сырой токен
    технической УЗ mcp-invest-service (без claim cus вообще) — invest-server слепо
    доверяет вызывающему слою. Это и есть новый, сервис-к-сервису, локус той же
    BAC-уязвимости (см. mcp-invest/auth.py — там она же, но на уровне агент→MCP).

    `mode` — переопределение режима на конкретный запрос через заголовок
    X-Demo-Auth-Mode, которое mcp-invest форвардит дальше вместе с исходящим Bearer-токеном.
    """
    effective_mode = mode if mode in ("vulnerable", "protected") else AUTH_MODE
    if effective_mode != "protected":
        return
    token_cus = claims.get("cus")
    if not token_cus:
        raise AuthError(
            "Токен не привязан к конкретному клиенту (нет claim 'cus') — "
            "в защищённом режиме сырой токен технической УЗ mcp-invest-service не даёт "
            "доступа к данным клиентов. Нужен токен, пробрасываемый от конкретного пользователя."
        )
    if str(token_cus) != str(requested_cus):
        raise AuthError(
            f"Токен ограничен клиентом cus={token_cus}, а запрошены данные клиента cus={requested_cus}. "
            "Доступ запрещён (защищённый режим)."
        )
