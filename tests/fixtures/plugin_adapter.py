"""An adapter that lives outside the package: used by the portability tests (P2-6).

A real plugin would read a source ``mcp_audit`` does not know (a systemd unit, a
Helm chart, a policy service).  This one only has to prove that registration
works from outside and that the new kind reaches the applicability plan.
"""
from mcp_audit.adapters.base import Adapter, AdapterResult
from mcp_audit.evidence import EvidenceStore
from mcp_audit.models import AuditDocument, Method, SourceType


class NotesAdapter(Adapter):
    kind = "notes_snapshot"
    adapter_version = "1.0.0"
    supported = ["notes"]
    unsupported = {"anything_else": "this adapter only reads its own note file"}

    def collect(self, doc: AuditDocument, store: EvidenceStore) -> AdapterResult:
        note = self.binding.binding.get("note") or "no note bound"
        store.add(SourceType.IMPORTED, Method.IMPORT, {"kind": "note"}, summary=str(note),
                  adapter=self.kind, adapter_version=self.adapter_version)
        return AdapterResult(self.status("available", evidence_count=1))
