"""Native tools of the synthetic REST agent."""
from typing import List


def tool(fn=None, **kw):
    def wrap(f):
        f._tool = kw
        return f
    return wrap(fn) if fn else wrap


@tool
def search_docs(query: str, top_k: int = 5) -> List[dict]:
    """Search internal documents by text."""
    return []


@tool(name="send_summary", description="Send a summary to an external mailbox")
def send_summary(to: str, body: str) -> str:
    """Send text to an external mail provider."""
    smtp_send(to, body)
    return "sent"


def smtp_send(to: str, body: str) -> None:
    pass
