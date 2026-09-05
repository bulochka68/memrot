"""Конфигурация стенда из переменных окружения."""

import os
from functools import lru_cache

from dotenv import load_dotenv

load_dotenv()


@lru_cache
def get_settings() -> "Settings":
    return Settings()


class Settings:
    redis_url: str = os.getenv("REDIS_URL", "redis://localhost:6379/0")
    mongo_uri: str = os.getenv("MONGO_URI", "mongodb://localhost:27017")
    mongo_db: str = os.getenv("MONGO_DB", "agent_memory")

    openai_api_key: str = os.getenv("OPENAI_API_KEY", "")
    openai_base_url: str | None = os.getenv("OPENAI_BASE_URL") or None

    mcp_invest_url: str | None = os.getenv("MCP_INVEST_URL") or None
    # Браузерный адрес ручки автотестирования (agent-api) — для примера в UI, поэтому
    # localhost, а не внутренний docker-хост (человек копирует сниппет к себе на машину).
    agent_api_url: str | None = os.getenv("AGENT_API_URL") or None

    keycloak_url: str | None = os.getenv("KEYCLOAK_URL") or None
    # Браузерный адрес Keycloak (в отличие от keycloak_url — внутреннего docker-хоста):
    # нужен для ссылок, по которым переходит сам браузер пользователя (logout).
    keycloak_issuer_url: str = os.getenv("KEYCLOAK_ISSUER_URL", "https://localhost:8443")
    keycloak_realm: str = os.getenv("KEYCLOAK_REALM", "genai-stand")
    agent_client_id: str = os.getenv("AGENT_CLIENT_ID", "agent-service")
    agent_client_secret: str = os.getenv("AGENT_CLIENT_SECRET", "agent-service-secret")
    ui_client_id: str = os.getenv("UI_CLIENT_ID", "streamlit-ui")
    ui_client_secret: str = os.getenv("UI_CLIENT_SECRET", "streamlit-ui-secret")
    streamlit_app_client_id: str = os.getenv("STREAMLIT_APP_CLIENT_ID", "streamlit-app")

    research_model: str = os.getenv("RESEARCH_MODEL", "openai:gpt-4o-mini")
    summarization_model: str = os.getenv("SUMMARIZATION_MODEL", "openai:gpt-4o-mini")

    working_memory_ttl: int = int(os.getenv("WORKING_MEMORY_TTL", "86400"))

    research_model_max_tokens: int = int(os.getenv("RESEARCH_MODEL_MAX_TOKENS", "2048"))
    summarization_model_max_tokens: int = int(os.getenv("SUMMARIZATION_MODEL_MAX_TOKENS", "1024"))
    max_react_tool_calls: int = int(os.getenv("MAX_REACT_TOOL_CALLS", "2"))

    max_dialog_sessions: int = int(os.getenv("MAX_DIALOG_SESSIONS", "5"))
    max_episodic_memories: int = int(os.getenv("MAX_EPISODIC_MEMORIES", "10"))
    max_semantic_memories: int = int(os.getenv("MAX_SEMANTIC_MEMORIES", "20"))
