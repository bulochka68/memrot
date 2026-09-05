"""Тулы агента, не относящиеся к MCP Инвеста."""

import asyncio
from typing import List

from langchain_core.tools import tool

try:
    from ddgs import DDGS
except ImportError:  # Backward compatibility for older installs
    from duckduckgo_search import DDGS

DUCKDUCKGO_SEARCH_DESCRIPTION = (
    "Search the web using DuckDuckGo. Useful for current events and factual research."
)


@tool(description=DUCKDUCKGO_SEARCH_DESCRIPTION)
async def duckduckgo_search(queries: List[str]) -> str:
    """Perform web searches via DuckDuckGo and return formatted results."""

    async def _search_one(query: str) -> dict:
        loop = asyncio.get_event_loop()

        def _sync_search() -> dict:
            results = []
            with DDGS() as ddgs:
                for i, item in enumerate(ddgs.text(query, max_results=5)):
                    results.append({
                        "title": item.get("title", ""),
                        "url": item.get("href", ""),
                        "content": item.get("body", ""),
                        "score": 1.0 - (i * 0.1),
                        "raw_content": item.get("body", ""),
                    })
            return {"query": query, "results": results}

        return await loop.run_in_executor(None, _sync_search)

    responses = await asyncio.gather(*[_search_one(q) for q in queries])
    parts = []
    for resp in responses:
        parts.append(f"Search: {resp['query']}")
        for r in resp.get("results", []):
            parts.append(f"- {r.get('title', '')}: {r.get('url', '')}\n  {r.get('content', '')[:500]}")
    return "\n\n".join(parts) if parts else "No results found."
