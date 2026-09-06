"""Memory store of the registry stand."""


class Palace:
    def mine_note(self, subject_id: str, text: str) -> dict:
        row = {"subject_id": subject_id, "text": text, "audience": "user", "source_refs": ["tool:vault_mine_note"]}
        self._execute("INSERT INTO drawers (subject_id, text, audience, source_refs) VALUES (%s, %s, 'user', %s)",
                      (subject_id, text, row["source_refs"]))
        return row

    def traverse(self, subject_id: str, query: str) -> list:
        return self._execute("SELECT text FROM drawers WHERE subject_id = %s AND text ILIKE %s", (subject_id, query))

    def build_context(self, subject_id: str) -> str:
        rows = self._execute("SELECT text FROM drawers WHERE subject_id = %s", (subject_id,))
        return "\n".join(f"[drawer] {r['text']}" for r in rows)

    def dissolve_wing(self, wing_id: str) -> dict:
        self._execute("DELETE FROM drawers WHERE wing_id = %s", (wing_id,))
        return {"wing_id": wing_id, "dissolved": True}

    def _execute(self, sql, params=()):
        return []
