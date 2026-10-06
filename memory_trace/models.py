"""Pydantic v2 models mirroring ``schemas/memory-trace-0.1.schema.json``.

Pure data shapes: no emitters, no business logic. Cross-field rules
(``allOf`` / ``if``-``then`` in the schema) live only in the JSON schema and
are enforced by ``memory_trace.schema.validate_event``.

Nullability follows the schema exactly:

* ``"type": [..., "null"]`` -> ``Optional[...] = None``;
* optional but non-nullable properties are typed without ``Optional`` and
  default to ``None``. Pydantic does not validate defaults, so omitting the
  field works while an explicit ``null`` is rejected, as in the schema.
"""
from __future__ import annotations

import enum
from typing import Any, Dict, List, Optional, Union
from uuid import UUID

from pydantic import AwareDatetime, BaseModel, ConfigDict, Field


# --------------------------------------------------------------------------- #
# Enumerations
# --------------------------------------------------------------------------- #

class Stage(str, enum.Enum):
    CANDIDATE = "candidate"
    SAVED = "saved"
    RETRIEVED = "retrieved"
    IN_PROMPT = "in_prompt"
    USED_IN_REASONING = "used_in_reasoning"
    INFLUENCED_ACTION = "influenced_action"
    CAUSED_HARM = "caused_harm"


class Principal(str, enum.Enum):
    ATTACKER = "attacker"
    VICTIM = "victim"
    TOOL = "tool"
    BUSINESS = "business"
    SYSTEM = "system"
    AUDITOR = "auditor"


class CoverageSource(str, enum.Enum):
    AGENT = "agent"
    STAND = "stand"
    MEMORY_STORE = "memory_store"
    TOOL = "tool"
    BUSINESS = "business"
    AUDITOR = "auditor"


class Operation(str, enum.Enum):
    WRITE = "write"
    UPDATE = "update"
    DELETE = "delete"


class MemoryLayer(str, enum.Enum):
    POLICY_GLOBAL = "policy_global"
    SEMANTIC = "semantic"
    EPISODIC = "episodic"
    SHARED = "shared"


class ContextRole(str, enum.Enum):
    SYSTEM = "system"
    USER = "user"
    TOOL = "tool"
    MEMORY = "memory"
    POLICY = "policy"


class ChainBreakReason(str, enum.Enum):
    SCOPE_MISMATCH = "scope_mismatch"
    PERSIST_MISS = "persist_miss"
    PARAPHRASE = "paraphrase"
    MISSING_IN_PROMPT = "missing_in_prompt"


class EvidenceTier(str, enum.Enum):
    TEXT = "text"
    STATE = "state"
    GROUND_TRUTH = "ground_truth"


class EvidenceKind(str, enum.Enum):
    HARD = "hard"
    SOFT = "soft"


class RetrievalMethod(str, enum.Enum):
    DENSE = "dense"
    SPARSE = "sparse"
    HYBRID = "hybrid"


class AccessDecision(str, enum.Enum):
    ALLOW = "allow"
    DENY = "deny"
    UNKNOWN = "unknown"


class DefenseVerdict(str, enum.Enum):
    ALLOW = "allow"
    DENY = "deny"
    REDACT = "redact"
    QUARANTINE = "quarantine"
    UNKNOWN = "unknown"


# --------------------------------------------------------------------------- #
# Models
# --------------------------------------------------------------------------- #

class _StrictModel(BaseModel):
    """``additionalProperties: false`` on every object in the schema."""

    model_config = ConfigDict(extra="forbid", populate_by_name=True)

    def to_dict(self) -> Dict[str, Any]:
        return self.model_dump(mode="json", by_alias=True, exclude_unset=True)


class Coverage(_StrictModel):
    observed: bool
    source: CoverageSource
    partial: bool


class FinalizeScopes(_StrictModel):
    requested_scopes: List[str] = None
    actual_scopes: List[str] = None
    facts_digest: List[str] = None


class ToolCall(_StrictModel):
    qualified_id: str = None
    args_digest: str = None
    access_decision: AccessDecision = None
    result_ref: Optional[str] = None


class DefenseDecision(_StrictModel):
    component: str = None
    verdict: DefenseVerdict = None
    reason: str = None


class BusinessObservation(_StrictModel):
    metric: str = None
    value: Union[bool, int, float, str] = None
    source: str = None
    evidence_kind: EvidenceKind = None


class TraceEvent(_StrictModel):
    # -- required ----------------------------------------------------------- #
    schema_version: str = Field(pattern=r"^0\.1\.[0-9]+$")
    event_id: UUID
    run_id: str = Field(min_length=1, max_length=128)
    trace_id: str = Field(min_length=1, max_length=128)
    agent_id: str = Field(min_length=1, max_length=128)
    principal: Principal
    component: str = Field(min_length=1, max_length=128)
    ts: AwareDatetime
    stage: Stage
    parent_event_refs: List[UUID]
    coverage: Coverage = Field(alias="_coverage")

    # -- identity / context -------------------------------------------------- #
    config_version: str = None
    session_id: Optional[str] = Field(default=None, min_length=1, max_length=128)

    # -- content ------------------------------------------------------------- #
    content_digest: str = Field(default=None, pattern=r"^sha256:[a-f0-9]{64}$")
    content_preview: str = Field(default=None, max_length=256)
    content_full: Optional[str] = None
    content_redacted: bool = None
    content_length: int = Field(default=None, ge=0)
    redaction_mode: Optional[str] = None

    # -- write ---------------------------------------------------------------- #
    writer_id: Optional[str] = None
    channel_id: Optional[str] = None
    operation: Optional[Operation] = None
    memory_layer: Optional[MemoryLayer] = None
    finalize_scopes: Optional[FinalizeScopes] = None

    # -- context assembly ---------------------------------------------------- #
    included_in_context: Optional[bool] = None
    context_role: Optional[ContextRole] = None
    rank_position: Optional[int] = Field(default=None, ge=0)
    prompt_block_id: Optional[str] = None

    # -- retrieval ------------------------------------------------------------ #
    embedding_score: Optional[float] = None
    retrieval_score: Optional[float] = None
    reranking_score: Optional[float] = None
    top_k: Optional[int] = Field(default=None, ge=1)
    cutoff_used: Optional[float] = None
    retrieval_method: Optional[RetrievalMethod] = None
    query_used: Optional[str] = None

    # -- action / defense / business ----------------------------------------- #
    tool_call: Optional[ToolCall] = None
    defense_decision: Optional[DefenseDecision] = None
    business_observation: Optional[BusinessObservation] = None

    # -- diagnosis ------------------------------------------------------------ #
    chain_break_reason: Optional[ChainBreakReason] = None
    evidence_tier: Optional[EvidenceTier] = None
    evidence_kind: Optional[EvidenceKind] = None

    experimental: bool = False
