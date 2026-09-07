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
import time
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from typing import Any, Dict, Optional

# HTTP statuses worth retrying: 429 (rate limit) and 5xx (server-side,
# transient). Never retry 4xx client errors like 401/400/403/404 -- an
# invalid key or a malformed request won't fix itself on the next attempt,
# and retrying just delays the (correct) failure.
_RETRYABLE_HTTP_STATUSES = frozenset({429, 500, 502, 503, 504})


@dataclass
class LLMClientConfig:
    base_url: str
    model: str
    api_key_env: Optional[str] = None   # unset -> no Authorization header (typical for local endpoints)
    timeout: float = 60.0
    extra_headers: Dict[str, str] = field(default_factory=dict)
    max_retries: int = 2   # additional attempts after the first, only for transient failures (see below)
    retry_backoff: float = 1.5   # seconds; attempt N waits retry_backoff * N before retrying


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
        """One chat-completion call; returns the assistant message content.

        Transient failures (429, 5xx, or a bare transport/connection error --
        e.g. a hosted gateway like OpenRouter dropping the TLS connection
        mid-handshake, seen live and confirmed non-deterministic: the exact
        same call succeeds on a bare retry) get up to ``config.max_retries``
        extra attempts with linear backoff before raising. A 4xx client error
        (bad key, malformed request) is raised immediately on the first
        attempt -- it will not fix itself."""
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

        attempts = max(0, self.config.max_retries) + 1
        last_exc: Optional[LLMClientError] = None
        data: Optional[dict] = None
        for attempt in range(attempts):
            try:
                with urllib.request.urlopen(req, timeout=self.config.timeout) as resp:
                    data = json.loads(resp.read().decode("utf-8"))
                break
            except urllib.error.HTTPError as exc:
                detail = exc.read().decode("utf-8", errors="replace") if exc.fp else ""
                last_exc = LLMClientError(f"HTTP {exc.code} from {self.config.base_url}: {detail[:500]}")
                if exc.code not in _RETRYABLE_HTTP_STATUSES or attempt == attempts - 1:
                    raise last_exc from exc
            except urllib.error.URLError as exc:
                last_exc = LLMClientError(f"transport error contacting {self.config.base_url}: {exc.reason}")
                if attempt == attempts - 1:
                    raise last_exc from exc
            time.sleep(self.config.retry_backoff * (attempt + 1))

        try:
            return data["choices"][0]["message"]["content"]
        except (KeyError, IndexError, TypeError) as exc:
            raise LLMClientError(f"unexpected chat.completions response shape: {data!r}") from exc
