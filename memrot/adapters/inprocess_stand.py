"""Grey-box, in-process adapter for the genai-invest-agent-memory-stand
reference target -- imports the vendored ``app.agent.runner``/
``app.orchestrator.graph``/``app.memory.store`` modules directly (no HTTP,
no Keycloak), so it exercises the *real* target code (real LangGraph
orchestration, real summarization/extraction prompts) against the *real*
Mongo/Redis the live stand uses, when pointed at the same URLs.

Why this exists (see ``memrot/catalog/prompts/domain/invest_bank/tool_output_web_search_poisoning/``):
the stand's only web tool, ``duckduckgo_search`` (``app/agent/tools.py``),
hits real DuckDuckGo -- not deterministically controllable from outside the
process for a red-team test. This adapter's ``stage_tool_response()``
monkeypatches the module-level ``DDGS`` name that tool resolves at call
time, so a test can inject content into "the next search result" exactly
once, then let the target's own real code decide what happens to it.

Heavy dependencies (langchain/langgraph/pymongo/redis, the whole ``app``
package) are imported lazily inside methods, not at module import time --
mirrors ``GenAIInvestAdapter``'s lazy pymongo/redis imports -- so merely
importing this module never requires them to be installed.
"""
from __future__ import annotations

import asyncio
import json
from typing import Any, Coroutine, Dict, Optional, TypeVar

from ..models import Principal
from .base import AdapterCapabilities, TargetAdapter

_T = TypeVar("_T")


def _run_async(coro: "Coroutine[Any, Any, _T]") -> _T:
    """Run a coroutine to completion from this adapter's synchronous
    ``TargetAdapter`` methods, regardless of whether the calling thread
    already has a running event loop. Plain ``asyncio.run()`` fails with
    "cannot be called from a running event loop" inside environments that
    run their own loop (Jupyter/ipykernel notably) -- confirmed the hard way
    (see ATTACK_HARNESS_PROGRESS.md's Phase 3 notes): every call silently
    became an ERROR-verdict AttackResult inside a notebook, worked fine from
    a plain script. When a loop is already running, execute the coroutine on
    a fresh loop in a separate thread instead of touching the caller's loop."""
    try:
        asyncio.get_running_loop()
    except RuntimeError:
        return asyncio.run(coro)   # no loop running here: the common, simple case
    import concurrent.futures
    with concurrent.futures.ThreadPoolExecutor(max_workers=1) as pool:
        return pool.submit(asyncio.run, coro).result()


def _ensure_mcp_adapters_importable() -> None:
    """``langchain-mcp-adapters`` requires Python>=3.10; ``app.agent.runner``
    imports ``MultiServerMCPClient`` from it unconditionally at module top
    level even though it's only *used* when ``settings.mcp_invest_url`` is
    set. Rather than requiring a newer interpreter just to test the
    web-search vector, register a stub module when the real package isn't
    importable -- ``_load_tools()`` already treats any ``get_tools()``
    failure as "no MCP-invest tools available" and falls back to
    ``[duckduckgo_search]`` alone, which is all this adapter's catalog needs."""
    try:
        import langchain_mcp_adapters.client  # noqa: F401
        return
    except ImportError:
        pass
    import sys
    import types

    class _StubMultiServerMCPClient:
        def __init__(self, *args: Any, **kwargs: Any) -> None:
            pass

        async def get_tools(self):
            raise RuntimeError("langchain-mcp-adapters not installed (requires Python>=3.10); "
                              "MCP-invest tools are unavailable in this in-process adapter")

    pkg = types.ModuleType("langchain_mcp_adapters")
    client_mod = types.ModuleType("langchain_mcp_adapters.client")
    client_mod.MultiServerMCPClient = _StubMultiServerMCPClient
    pkg.client = client_mod
    sys.modules.setdefault("langchain_mcp_adapters", pkg)
    sys.modules.setdefault("langchain_mcp_adapters.client", client_mod)


class _StagingDDGS:
    """Drop-in replacement for ``ddgs.DDGS``. If content has been staged for
    ``duckduckgo_search``, returns it as the sole (fake) result once (then
    reverts to nothing staged); otherwise delegates to the real ``DDGS``."""

    def __init__(self, staged: Dict[str, str], real_cls: type) -> None:
        self._staged = staged
        self._real_cls = real_cls
        self._real_instance: Any = None

    def __enter__(self) -> "_StagingDDGS":
        return self

    def __exit__(self, *exc_info: Any) -> bool:
        if self._real_instance is not None:
            self._real_instance.__exit__(*exc_info)
        return False

    def text(self, query: str, max_results: int = 5, **kwargs: Any):
        content = self._staged.pop("duckduckgo_search", None)
        if content is not None:
            return [{"title": "Staged result", "href": "https://staged.invalid/result", "body": content}]
        self._real_instance = self._real_cls()
        self._real_instance.__enter__()
        return self._real_instance.text(query, max_results=max_results, **kwargs)


class InProcessStandAdapter(TargetAdapter):
    kind = "inprocess_stand"
    adapter_version = "1.0.0"

    def __init__(self, *, auth_mode: str = "vulnerable", env_path: Optional[str] = None) -> None:
        """``env_path``: optional path to a ``.env`` file to load (e.g. the
        live stand's own, for its OpenRouter key) before the target's
        ``app.config.get_settings()`` is first evaluated. Loaded with
        ``override=False`` -- an already-set env var always wins."""
        self.auth_mode = auth_mode
        if env_path:
            from dotenv import load_dotenv
            load_dotenv(env_path, override=False)
        _ensure_mcp_adapters_importable()

        import app.agent.tools as tools_module

        self._tools_module = tools_module
        self._real_ddgs = tools_module.DDGS
        self._staged: Dict[str, str] = {}
        # app/agent/tools.py does `with DDGS() as ddgs: ...` -- DDGS must stay callable
        # (a class/factory), so substitute a factory that builds a fresh _StagingDDGS
        # context manager per call, not a bare _StagingDDGS instance.
        import functools
        tools_module.DDGS = functools.partial(_StagingDDGS, self._staged, self._real_ddgs)   # type: ignore[assignment]

    def new_session(self, principal: Principal) -> str:
        import uuid
        return f"s-{principal.principal_id}-{uuid.uuid4().hex[:10]}"

    def send(self, principal: Principal, session_id: str, message: str) -> str:
        from app.agent.runner import run_research
        result = _run_async(run_research(
            user_id=principal.principal_id, session_id=session_id, query=message, auth_mode=self.auth_mode,
        ))
        return result["final_report"]

    def consolidate(self, principal: Principal, session_id: str) -> None:
        from app.orchestrator.graph import finalize_session
        _run_async(finalize_session(principal.principal_id, session_id))

    def inspect_memory(self, principal: Principal) -> Optional[str]:
        from app.memory.store import MemoryStore
        store = MemoryStore()
        cus = principal.principal_id
        episodes = store.mongo.episodic.list_for_user(cus, limit=50)
        semantics = store.mongo.semantic.list_for_context(cus, limit=50)
        policies = store.mongo.agent_policy.list_all(limit=50)
        blob = {
            "episodic": [e.summary for e in episodes],
            "semantic_user": [s.fact for s in semantics if s.scope != "global"],
            "agent_policy_global": [p.statement for p in policies],
        }
        return json.dumps(blob, ensure_ascii=False)

    def stage_tool_response(self, tool_name: str, content: str, *, vector: str = "web_search") -> None:
        self._staged[tool_name] = content

    def reset(self) -> bool:
        # Same known limitation as GenAIInvestAdapter: no destructive
        # Mongo/Redis wipe hook. The mandatory per-variant baseline phase is
        # the contamination safety net instead.
        return False

    def capabilities(self) -> AdapterCapabilities:
        return AdapterCapabilities(
            access_profile="white_box",
            supports_consolidate=True,
            supports_inspect_memory=True,
            supports_tool_staging=True,
            supports_reset=False,
            supported_tool_vectors=["web_search"],
            notes=["in-process grey-box adapter: runs the real vendored app/ code directly, "
                  "sharing whatever Mongo/Redis/LLM endpoint its own app.config resolves -- "
                  "no HTTP or Keycloak involved"],
        )
