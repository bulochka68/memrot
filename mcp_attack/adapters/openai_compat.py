"""Generic OpenAI-compatible chat adapter.

Stdlib only (``urllib``) -- the black-box path never requires a third-party
HTTP or SDK dependency. Any target exposing ``POST {base_url}/chat/completions``
with ``Authorization: Bearer <key>`` works: mint one credential per principal
via ``MCP_ATTACK_CRED_<credential_ref>`` and point ``base_url``/``model`` at it.
"""
from __future__ import annotations

import json
import os
import urllib.error
import urllib.request
import uuid
from typing import Any, Dict, List, Optional

from ..models import Principal
from .base import AdapterCapabilities, TargetAdapter


def credential_for(principal: Principal) -> str:
    ref = principal.credential_ref or principal.principal_id
    env_name = f"MCP_ATTACK_CRED_{ref}"
    value = os.environ.get(env_name)
    if not value:
        raise RuntimeError(
            f"missing credential: set {env_name} for principal {principal.principal_id!r} "
            f"(credential_ref={principal.credential_ref!r})"
        )
    return value


class OpenAICompatAdapter(TargetAdapter):
    kind = "openai_compat"
    adapter_version = "1.0.0"

    def __init__(self, *, base_url: str, model: str, timeout: float = 30.0,
                 extra_headers: Optional[Dict[str, str]] = None,
                 session_header: str = "X-Conversation-Id") -> None:
        self.base_url = base_url.rstrip("/")
        self.model = model
        self.timeout = timeout
        self.extra_headers = dict(extra_headers or {})
        self.session_header = session_header
        self._sessions: Dict[str, str] = {}   # channel key -> last session id (informational only)

    # -- session bookkeeping ------------------------------------------------ #
    def new_session(self, principal: Principal) -> str:
        session_id = f"s-{uuid.uuid4().hex[:12]}"
        self._sessions[principal.principal_id] = session_id
        return session_id

    def _extra_body(self, session_id: str) -> Dict[str, Any]:
        return {}

    def _endpoint(self) -> str:
        return f"{self.base_url}/chat/completions"

    def _build_body(self, session_id: str, message: str) -> Dict[str, Any]:
        body: Dict[str, Any] = {
            "model": self.model,
            "messages": [{"role": "user", "content": message}],
        }
        body.update(self._extra_body(session_id))
        return body

    def _extract_content(self, data: Any) -> str:
        try:
            return data["choices"][0]["message"]["content"]
        except (KeyError, IndexError, TypeError) as exc:
            raise RuntimeError(f"unexpected chat.completions response shape: {data!r}") from exc

    def send(self, principal: Principal, session_id: str, message: str) -> str:
        key = credential_for(principal)
        body = self._build_body(session_id, message)
        headers = {
            "Authorization": f"Bearer {key}",
            "Content-Type": "application/json",
            self.session_header: session_id,
            **self.extra_headers,
        }
        req = urllib.request.Request(
            self._endpoint(),
            data=json.dumps(body).encode("utf-8"),
            headers=headers,
            method="POST",
        )
        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                data = json.loads(resp.read().decode("utf-8"))
        except urllib.error.HTTPError as exc:
            detail = exc.read().decode("utf-8", errors="replace") if exc.fp else ""
            raise RuntimeError(f"HTTP {exc.code} from {self.base_url}: {detail[:500]}") from exc
        except urllib.error.URLError as exc:
            raise RuntimeError(f"transport error contacting {self.base_url}: {exc.reason}") from exc
        return self._extract_content(data)

    def capabilities(self) -> AdapterCapabilities:
        return AdapterCapabilities(access_profile="black_box")


def _dig(data: Any, path: str) -> Any:
    cur = data
    for part in path.split("."):
        if cur is None:
            raise KeyError(path)
        if part.isdigit():
            cur = cur[int(part)]
        else:
            cur = cur[part]
    return cur


class HTTPGenericAdapter(OpenAICompatAdapter):
    """Thin OpenAICompat subclass with configurable request/response field
    mapping so a non-OpenAI HTTP agent can be bound from JSON config."""
    kind = "http_generic"
    adapter_version = "1.0.0"

    def __init__(self, *, base_url: str, model: str = "", timeout: float = 30.0,
                 extra_headers: Optional[Dict[str, str]] = None,
                 session_header: str = "X-Conversation-Id",
                 response_path: str = "choices.0.message.content",
                 messages_field: str = "messages",
                 session_in_body: bool = False,
                 session_body_field: str = "conversation_id",
                 chat_path: str = "/chat/completions") -> None:
        super().__init__(base_url=base_url, model=model or "default", timeout=timeout,
                         extra_headers=extra_headers, session_header=session_header)
        self.response_path = response_path
        self.messages_field = messages_field
        self.session_in_body = session_in_body
        self.session_body_field = session_body_field
        path = chat_path if chat_path.startswith("/") else f"/{chat_path}"
        self.chat_path = path

    def _endpoint(self) -> str:
        return f"{self.base_url}{self.chat_path}"

    def _extra_body(self, session_id: str) -> Dict[str, Any]:
        if self.session_in_body:
            return {self.session_body_field: session_id}
        return {}

    def _build_body(self, session_id: str, message: str) -> Dict[str, Any]:
        body: Dict[str, Any] = {
            "model": self.model,
            self.messages_field: [{"role": "user", "content": message}],
        }
        body.update(self._extra_body(session_id))
        return body

    def _extract_content(self, data: Any) -> str:
        try:
            value = _dig(data, self.response_path)
        except (KeyError, IndexError, TypeError) as exc:
            raise RuntimeError(f"unexpected response shape at {self.response_path!r}: {data!r}") from exc
        return "" if value is None else str(value)
