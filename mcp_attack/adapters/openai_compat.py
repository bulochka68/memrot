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

    def send(self, principal: Principal, session_id: str, message: str) -> str:
        key = credential_for(principal)
        body: Dict[str, Any] = {
            "model": self.model,
            "messages": [{"role": "user", "content": message}],
        }
        body.update(self._extra_body(session_id))
        headers = {
            "Authorization": f"Bearer {key}",
            "Content-Type": "application/json",
            self.session_header: session_id,
            **self.extra_headers,
        }
        req = urllib.request.Request(
            f"{self.base_url}/chat/completions",
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
        try:
            return data["choices"][0]["message"]["content"]
        except (KeyError, IndexError, TypeError) as exc:
            raise RuntimeError(f"unexpected chat.completions response shape: {data!r}") from exc

    def capabilities(self) -> AdapterCapabilities:
        return AdapterCapabilities(access_profile="black_box")
