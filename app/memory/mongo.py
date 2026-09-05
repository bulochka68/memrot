"""Долговременная память в MongoDB."""

from pymongo import ASCENDING, DESCENDING, MongoClient
from pymongo.collection import Collection

from app.config import get_settings
from app.memory.models import AgentPolicyMemory, ApiKey, DialogSession, EpisodicMemory, SemanticMemory


class MongoMemoryStore:
    def __init__(self, client: MongoClient | None = None):
        settings = get_settings()
        self._client = client or MongoClient(settings.mongo_uri)
        self._db = self._client[settings.mongo_db]
        self._ensure_indexes()

    def _ensure_indexes(self) -> None:
        self.dialog.col.create_index([("user_id", ASCENDING), ("ended_at", DESCENDING)])
        self.episodic.col.create_index([("user_id", ASCENDING), ("created_at", DESCENDING)])
        self.semantic.col.create_index([("scope", ASCENDING), ("user_id", ASCENDING)])
        self.agent_policy.col.create_index([("created_at", DESCENDING)])
        self.api_keys.col.create_index([("key_hash", ASCENDING)], unique=True)
        self.api_keys.col.create_index([("user_id", ASCENDING)])

    @property
    def dialog(self) -> "DialogRepo":
        return DialogRepo(self._db["dialog_sessions"])

    @property
    def episodic(self) -> "EpisodicRepo":
        return EpisodicRepo(self._db["episodic_memories"])

    @property
    def semantic(self) -> "SemanticRepo":
        return SemanticRepo(self._db["semantic_memories"])

    @property
    def agent_policy(self) -> "AgentPolicyRepo":
        return AgentPolicyRepo(self._db["agent_policy_memories"])

    @property
    def api_keys(self) -> "ApiKeyRepo":
        return ApiKeyRepo(self._db["api_keys"])


class DialogRepo:
    def __init__(self, col: Collection):
        self.col = col

    def save_session(self, session: DialogSession) -> str:
        doc = session.model_dump(mode="json")
        self.col.replace_one(
            {"user_id": session.user_id, "session_id": session.session_id},
            doc,
            upsert=True,
        )
        return session.session_id

    def list_for_user(
        self, user_id: str, limit: int = 5, *, trusted_only: bool = True
    ) -> list[DialogSession]:
        cursor = self.col.find({"user_id": user_id}).sort("ended_at", DESCENDING).limit(limit)
        out = []
        for doc in cursor:
            if trusted_only and not _doc_trusted(doc, user_id):
                continue
            doc.pop("_id", None)
            out.append(DialogSession.model_validate(doc))
        return out


class EpisodicRepo:
    def __init__(self, col: Collection):
        self.col = col

    def insert_many(self, episodes: list[EpisodicMemory]) -> None:
        for ep in episodes:
            doc = ep.model_dump(mode="json")
            self.col.insert_one(doc)

    def list_for_user(
        self, user_id: str, limit: int = 10, *, trusted_only: bool = True
    ) -> list[EpisodicMemory]:
        cursor = self.col.find({"user_id": user_id}).sort("created_at", DESCENDING).limit(limit)
        out = []
        for doc in cursor:
            if trusted_only and not _doc_trusted(doc, user_id):
                continue
            doc.pop("_id", None)
            out.append(EpisodicMemory.model_validate(doc))
        return out


class SemanticRepo:
    def __init__(self, col: Collection):
        self.col = col

    def insert_many(self, facts: list[SemanticMemory]) -> None:
        for fact in facts:
            doc = fact.model_dump(mode="json")
            self.col.insert_one(doc)

    def list_for_context(
        self, user_id: str, limit: int = 20, *, trusted_only: bool = True
    ) -> list[SemanticMemory]:
        query = {"$or": [{"scope": "global"}, {"user_id": user_id, "scope": "user"}]}
        cursor = self.col.find(query).sort("created_at", DESCENDING).limit(limit)
        out = []
        for doc in cursor:
            if trusted_only and not _doc_trusted(doc, user_id, allow_global=True):
                continue
            doc.pop("_id", None)
            out.append(SemanticMemory.model_validate(doc))
        return out


class AgentPolicyRepo:
    """Уровень памяти "политика агента" — структурно не привязан ни к одному пользователю.

    Любая запись здесь читается и влияет на ответы ВСЕМ клиентам — по дизайну, без scoping.
    """

    def __init__(self, col: Collection):
        self.col = col

    def insert_many(self, policies: list[AgentPolicyMemory]) -> None:
        for policy in policies:
            self.col.insert_one(policy.model_dump(mode="json"))

    def list_all(self, limit: int = 20) -> list[AgentPolicyMemory]:
        cursor = self.col.find({}).sort("created_at", DESCENDING).limit(limit)
        out = []
        for doc in cursor:
            doc.pop("_id", None)
            out.append(AgentPolicyMemory.model_validate(doc))
        return out


class ApiKeyRepo:
    """Долгоживущие API-ключи для headless-доступа к агенту (см. app/apikeys.py, app/api_server.py)."""

    def __init__(self, col: Collection):
        self.col = col

    def create(self, key: ApiKey) -> None:
        self.col.insert_one(key.model_dump(mode="json"))

    def find_by_hash(self, key_hash: str) -> ApiKey | None:
        doc = self.col.find_one({"key_hash": key_hash, "revoked": False})
        if not doc:
            return None
        doc.pop("_id", None)
        return ApiKey.model_validate(doc)

    def list_for_user(self, user_id: str) -> list[ApiKey]:
        cursor = self.col.find({"user_id": user_id}).sort("created_at", DESCENDING)
        out = []
        for doc in cursor:
            doc.pop("_id", None)
            out.append(ApiKey.model_validate(doc))
        return out

    def revoke(self, key_id: str, user_id: str) -> None:
        self.col.update_one({"key_id": key_id, "user_id": user_id}, {"$set": {"revoked": True}})


def _doc_trusted(doc: dict, user_id: str, *, allow_global: bool = False) -> bool:
    if allow_global and doc.get("scope") == "global":
        return True
    if doc.get("user_id") and doc.get("user_id") != user_id:
        return False
    return True
