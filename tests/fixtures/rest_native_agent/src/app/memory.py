"""pgvector-backed memory with server-side scope resolution and a separate publisher."""
import psycopg


class VectorMemory:
    def __init__(self):
        self.conn = psycopg.connect("postgresql://memory")

    def build_context(self, subject: str) -> str:
        rows = self.conn.execute(
            "SELECT text FROM notes WHERE subject_id = %s ORDER BY embedding <-> %s LIMIT 10", (subject, subject)
        ).fetchall()
        rules = self.conn.execute("SELECT text FROM rules WHERE review_state = 'approved'").fetchall()
        blocks = ["[data] " + r[0] for r in rows] + ["[rule:approved] " + r[0] for r in rules]
        return "\n".join(blocks)

    def write_note(self, subject: str, text: str, source_refs: list) -> None:
        # audience is always the authenticated subject; the model never proposes a scope
        self.conn.execute(
            "INSERT INTO notes (subject_id, text, source_refs, audience) VALUES (%s, %s, %s, 'user')",
            (subject, text, source_refs),
        )

    def get_document(self, doc_id: str) -> dict:
        return {"owner": "x", "text": ""}


class RulePublisher:
    """Only the policy admin publishes shared rules, after review."""

    def publish(self, text: str, approver: str, approval_ref: str) -> None:
        assert approver == "policy-admin"
        self.conn.execute(
            "INSERT INTO rules (text, review_state, approval_ref, publisher) VALUES (%s, 'approved', %s, 'policy-admin')",
            (text, approval_ref),
        )
