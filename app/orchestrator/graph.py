"""Оркестратор памяти: финализация сессии."""

from typing import TypedDict

from langchain.chat_models import init_chat_model
from langchain_core.messages import HumanMessage
from langgraph.graph import END, START, StateGraph
from pydantic import BaseModel, Field

from app.config import get_settings
from app.memory.models import AgentPolicyMemory, EpisodicMemory, SemanticMemory
from app.memory.store import MemoryStore
from app.orchestrator import prompts


class EpisodeItem(BaseModel):
    summary: str


class EpisodesList(BaseModel):
    episodes: list[EpisodeItem] = Field(default_factory=list)


class SemanticItem(BaseModel):
    fact: str
    scope: str = "user"
    confidence: float = 0.8


class SemanticFactsList(BaseModel):
    facts: list[SemanticItem] = Field(default_factory=list)


class OrchestratorState(TypedDict):
    user_id: str
    session_id: str
    dialog_text: str
    session_summary: str
    episodes: list[dict]
    semantic_facts: list[dict]


def _model():
    settings = get_settings()
    kwargs = {
        "api_key": settings.openai_api_key,
        "max_tokens": settings.summarization_model_max_tokens,
        "extra_body": {"think": False},
    }
    if settings.openai_base_url:
        kwargs["base_url"] = settings.openai_base_url
    return init_chat_model(settings.summarization_model, **kwargs)


async def load_working(state: OrchestratorState) -> dict:
    store = MemoryStore()
    wm = store.get_working(state["user_id"], state["session_id"])
    lines = [f"[{m.role}] {m.content}" for m in wm.messages]
    return {"dialog_text": "\n".join(lines) if lines else "(пустая сессия)"}


async def summarize_dialog(state: OrchestratorState) -> dict:
    model = _model()
    prompt = prompts.SUMMARIZE_DIALOG.format(dialog=state["dialog_text"])
    resp = await model.ainvoke([HumanMessage(content=prompt)])
    return {"session_summary": resp.content}


async def extract_episodes(state: OrchestratorState) -> dict:
    model = _model().with_structured_output(EpisodesList)
    prompt = prompts.EXTRACT_EPISODES.format(
        summary=state["session_summary"],
        user_id=state["user_id"],
        session_id=state["session_id"],
    )
    result: EpisodesList = await model.ainvoke([HumanMessage(content=prompt)])
    episodes = [{"summary": e.summary} for e in result.episodes]
    if not episodes and state["session_summary"]:
        episodes = [{"summary": state["session_summary"]}]
    return {"episodes": episodes}


async def extract_semantics(state: OrchestratorState) -> dict:
    model = _model().with_structured_output(SemanticFactsList)
    ep_text = "\n".join(f"- {e['summary']}" for e in state["episodes"])
    prompt = prompts.EXTRACT_SEMANTICS.format(episodes=ep_text)
    result: SemanticFactsList = await model.ainvoke([HumanMessage(content=prompt)])
    return {"semantic_facts": [f.model_dump() for f in result.facts]}


async def persist_all(state: OrchestratorState) -> dict:
    store = MemoryStore()
    user_id = state["user_id"]
    session_id = state["session_id"]

    wm = store.get_working(user_id, session_id)
    if wm.messages:
        store.persist_dialog(user_id, session_id, wm.messages)

    episodes = [
        EpisodicMemory(
            user_id=user_id,
            session_id=session_id,
            summary=e["summary"],
            source_session=session_id,
        )
        for e in state["episodes"]
    ]
    if episodes:
        store.save_episodes(episodes)

    facts = []
    policies = []
    for f in state["semantic_facts"]:
        scope = f.get("scope", "user")
        if scope not in ("user", "global"):
            scope = "user"
        if scope == "global":
            policies.append(
                AgentPolicyMemory(
                    statement=f["fact"],
                    confidence=float(f.get("confidence", 0.8)),
                    source_session_id=session_id,
                )
            )
        else:
            facts.append(
                SemanticMemory(
                    fact=f["fact"],
                    scope="user",
                    user_id=user_id,
                    confidence=float(f.get("confidence", 0.8)),
                    source_episode_id=episodes[0].episode_id if episodes else None,
                )
            )
    if facts:
        store.save_semantics(facts)
    if policies:
        store.save_agent_policy(policies)

    wm.summary = state["session_summary"]
    store.working.save(user_id, session_id, wm)
    return {}


async def clear_working(state: OrchestratorState) -> dict:
    MemoryStore().clear_working(state["user_id"], state["session_id"])
    return {}


_builder = StateGraph(OrchestratorState)
_builder.add_node("load_working", load_working)
_builder.add_node("summarize_dialog", summarize_dialog)
_builder.add_node("extract_episodes", extract_episodes)
_builder.add_node("extract_semantics", extract_semantics)
_builder.add_node("persist_all", persist_all)
_builder.add_node("clear_working", clear_working)

_builder.add_edge(START, "load_working")
_builder.add_edge("load_working", "summarize_dialog")
_builder.add_edge("summarize_dialog", "extract_episodes")
_builder.add_edge("extract_episodes", "extract_semantics")
_builder.add_edge("extract_semantics", "persist_all")
_builder.add_edge("persist_all", "clear_working")
_builder.add_edge("clear_working", END)

_orchestrator = _builder.compile()


async def finalize_session(user_id: str, session_id: str) -> dict:
    """Запустить оркестратор и вернуть итоговое состояние."""
    return await _orchestrator.ainvoke(
        {"user_id": user_id, "session_id": session_id}
    )
