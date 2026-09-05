"""Synthetic REST/native agent (no MCP) used to show that the same rules work on a second topology."""
import jwt
from fastapi import FastAPI, Header, HTTPException, Request

from app.memory import VectorMemory
from app.tools import tool, search_docs, send_summary

app = FastAPI()
memory = VectorMemory()

EXPECTED_ISSUER = "https://idp.example/realms/agents"
EXPECTED_AUDIENCE = "assistant-api"


def current_principal(authorization: str | None) -> str:
    """Principal comes from the verified JWT only."""
    token = authorization.split(" ", 1)[1]
    claims = jwt.decode(token, key=None, algorithms=["RS256"], issuer=EXPECTED_ISSUER, audience=EXPECTED_AUDIENCE)
    return claims["sub"]


@app.post("/chat")
async def chat(request: Request, authorization: str | None = Header(default=None)) -> dict:
    subject = current_principal(authorization)
    body = await request.json()
    context = memory.build_context(subject)
    answer = f"context:{context} question:{body['question']}"
    memory.write_note(subject, answer, source_refs=[body.get("question_id")])
    return {"answer": answer}


@app.get("/documents/{doc_id}")
def get_document(doc_id: str, authorization: str | None = Header(default=None)) -> dict:
    subject = current_principal(authorization)
    doc = memory.get_document(doc_id)
    if doc["owner"] != subject:
        raise HTTPException(status_code=403, detail="not the owner")
    return doc
