"""One pluggable, OpenAI-compatible LLM client used by both the mutation
generator and the judge detector.

Deliberately a single class rather than two ("hosted API" vs "local"): any
hosted API (OpenAI, a bank-internal gateway, ...) and any local server
(Ollama, vLLM, LM Studio, ...) that exposes ``POST {base_url}/chat/completions``
are the same shape from here -- only ``base_url``/``model``/``api_key_env``
differ, so a caller switches between them purely through config, never code.
Mirrors ``adapters/openai_compat.py``'s stdlib-``urllib`` choice: the mutation
path never requires a third-party HTTP or SDK dependency either.

Two independent instances are expected in normal use -- one configured as the
"attacker"/mutation model, one as the judge -- per this project's own
observation that attacker and judge models should differ (e.g. a model that
is a strong attacker against a given target is not necessarily a good judge
of that same target's responses, and vice versa).
"""
from __future__ import annotations

import json
import os
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from typing import Any, Dict, Optional


@dataclass
class LLMClientConfig:
    base_url: str
    model: str
    api_key_env: Optional[str] = None   # unset -> no Authorization header (typical for local endpoints)
    timeout: float = 60.0
    extra_headers: Dict[str, str] = field(default_factory=dict)


class LLMClientError(RuntimeError):
    """Wraps any failure talking to the configured LLM (transport, HTTP, or
    an unexpected response shape) so callers can catch one exception type."""


class LLMClient:
    def __init__(self, config: LLMClientConfig) -> None:
        self.config = config

    def _api_key(self) -> Optional[str]:
        if not self.config.api_key_env:
            return None
        return os.environ.get(self.config.api_key_env)

    def complete(self, *, system: str, user: str, temperature: float = 0.9, max_tokens: int = 800) -> str:
        """One chat-completion call; returns the assistant message content."""
        body: Dict[str, Any] = {
            "model": self.config.model,
            "messages": [{"role": "system", "content": system}, {"role": "user", "content": user}],
            "temperature": temperature,
            "max_tokens": max_tokens,
        }
        headers = {"Content-Type": "application/json", **self.config.extra_headers}
        key = self._api_key()
        if key:
            headers["Authorization"] = f"Bearer {key}"

        req = urllib.request.Request(
            f"{self.config.base_url.rstrip('/')}/chat/completions",
            data=json.dumps(body).encode("utf-8"),
            headers=headers,
            method="POST",
        )
        try:
            with urllib.request.urlopen(req, timeout=self.config.timeout) as resp:
                data = json.loads(resp.read().decode("utf-8"))
        except urllib.error.HTTPError as exc:
            detail = exc.read().decode("utf-8", errors="replace") if exc.fp else ""
            raise LLMClientError(f"HTTP {exc.code} from {self.config.base_url}: {detail[:500]}") from exc
        except urllib.error.URLError as exc:
            raise LLMClientError(f"transport error contacting {self.config.base_url}: {exc.reason}") from exc
        try:
            return data["choices"][0]["message"]["content"]
        except (KeyError, IndexError, TypeError) as exc:
            raise LLMClientError(f"unexpected chat.completions response shape: {data!r}") from exc
