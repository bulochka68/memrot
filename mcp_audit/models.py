"""Single data model shared by all layers == the ``agent-security-audit v2.0`` JSON.

Everything the orchestrator passes between layers lives here, so the
in-memory representation and the emitted artifact never diverge.

Design rules (TZ §12, §15):

* every statement is a :class:`Claim` with its own ``claim_status``,
  ``evidence_refs``, ``scope``, ``confidence`` and ``limitations``;
* there is no tool-wide or report-wide ``verified`` flag;
* control checks separate *execution* (``execution_status``) from the
  *control outcome* (``control_outcome``);
* memory observations are recorded per stage (W / R / C / B) and are
  never collapsed into a single "verified";
* unknown stays unknown: no default allow, no default deny, no 100 % when
  the denominator is unknown.
"""
from __future__ import annotations

import enum
import hashlib
import json
import time
from dataclasses import dataclass, field, fields, is_dataclass
from typing import Any, Dict, Iterable, List, Optional


# --------------------------------------------------------------------------- #
# Helpers
# --------------------------------------------------------------------------- #

def plain(obj: Any) -> Any:
    """Recursively convert dataclasses / enums into JSON-ready values."""
    if isinstance(obj, enum.Enum):
        return obj.value
    if is_dataclass(obj) and not isinstance(obj, type):
        if hasattr(obj, "to_dict"):
            return obj.to_dict()
        return {f.name: plain(getattr(obj, f.name)) for f in fields(obj) if not f.name.startswith("_")}
    if isinstance(obj, dict):
        return {str(k): plain(v) for k, v in obj.items()}
    if isinstance(obj, (list, tuple, set, frozenset)):
        return [plain(v) for v in (sorted(obj) if isinstance(obj, (set, frozenset)) else obj)]
    return obj


def stable_id(prefix: str, *parts: Any, length: int = 10) -> str:
    """Deterministic identifier from semantic parts (never from list position)."""
    payload = "|".join("" if p is None else json.dumps(plain(p), sort_keys=True, ensure_ascii=False)
                       for p in parts)
    return f"{prefix}-{hashlib.sha256(payload.encode('utf-8')).hexdigest()[:length]}"


def digest(obj: Any) -> str:
    return "sha256:" + hashlib.sha256(
        json.dumps(plain(obj), sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    ).hexdigest()


# --------------------------------------------------------------------------- #
# Vocabularies
# --------------------------------------------------------------------------- #

class SourceType(str, enum.Enum):
    CONFIG = "config"
    DEFINITION = "definition"
    SOURCE_CODE = "source_code"
    POLICY_SNAPSHOT = "policy_snapshot"
    DEPLOYMENT_SNAPSHOT = "deployment_snapshot"
    MEMORY_SNAPSHOT = "memory_snapshot"
    RUNTIME_TRACE = "runtime_trace"
    FIXTURE_OBSERVATION = "fixture_observation"
    BASELINE = "baseline"
    IMPORTED = "imported"


RUNTIME_SOURCE_TYPES = frozenset({SourceType.RUNTIME_TRACE, SourceType.FIXTURE_OBSERVATION})


class Method(str, enum.Enum):
    PARSING = "parsing"
    STATIC_ANALYSIS = "static_analysis"
    POLICY_INSPECTION = "policy_inspection"
    OBSERVATION = "observation"
    CONTROLLED_VALIDATION = "controlled_validation"
    IMPORT = "import"


class ClaimStatus(str, enum.Enum):
    HYPOTHESIS = "hypothesis"
    STATIC_SUPPORTED = "static_supported"
    RUNTIME_SUPPORTED = "runtime_supported"
    CONTRADICTED = "contradicted"
    INCONCLUSIVE = "inconclusive"


class Confidence(str, enum.Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    UNKNOWN = "unknown"


class ControlOutcome(str, enum.Enum):
    PASS = "PASS"
    FAIL = "FAIL"
    INCONCLUSIVE = "INCONCLUSIVE"
    NOT_EVALUATED = "NOT_EVALUATED"
    NOT_APPLICABLE = "NOT_APPLICABLE"


class ExecutionStatus(str, enum.Enum):
    COMPLETED = "completed"
    ERROR = "error"
    TIMEOUT = "timeout"
    SKIPPED = "skipped"


class Applicability(str, enum.Enum):
    APPLICABLE = "applicable"
    NOT_APPLICABLE = "not_applicable"
    UNKNOWN = "unknown"


class StageObservation(str, enum.Enum):
    OBSERVED = "observed"
    NOT_OBSERVED = "not_observed"
    UNKNOWN = "unknown"
    NOT_EVALUATED = "not_evaluated"


MEMORY_STAGES = ("W", "R", "C", "B")   # written, retrieved, context included, behaviour observed


class KnowledgeState(str, enum.Enum):
    KNOWN = "known"
    ASSUMED = "assumed"
    UNKNOWN = "unknown"
    CONTRADICTORY = "contradictory"


class PathState(str, enum.Enum):
    CAPABILITY_COMBINATION = "capability_combination"
    STATIC_PATH_SUPPORTED = "static_path_supported"
    RUNTIME_PATH_OBSERVED = "runtime_path_observed"
    CONTROL_VIOLATION_OBSERVED = "control_violation_observed"
    UNKNOWN = "unknown"


class AssessmentState(str, enum.Enum):
    COMPLETE_FOR_SCOPE = "complete_for_scope"
    PARTIAL = "partial"
    NOT_ASSESSED = "not_assessed"


class SecurityConclusion(str, enum.Enum):
    FINDINGS_PRESENT = "findings_present"
    NO_VIOLATIONS_OBSERVED = "no_violations_observed"
    UNDETERMINED = "undetermined"


class RunMode(str, enum.Enum):
    OFFLINE = "offline"
    LIVE_INVENTORY = "live_inventory"
    TRACE_REVIEW = "trace_review"
    CONTROLLED_VALIDATION = "controlled_validation"
    BASELINE_COMPARISON = "baseline_comparison"

    @property
    def spawns_processes(self) -> bool:
        return self in (RunMode.LIVE_INVENTORY, RunMode.CONTROLLED_VALIDATION)


# Legacy v1 mode names are accepted as aliases (TZ §18).
LEGACY_MODE_ALIASES = {
    "passive": RunMode.OFFLINE,
    "active": RunMode.CONTROLLED_VALIDATION,
    "drift": RunMode.BASELINE_COMPARISON,
}


class Mode(str, enum.Enum):
    """Backward-compatible alias enum (v1 names).  Prefer :class:`RunMode`."""
    PASSIVE = "passive"
    ACTIVE = "active"
    DRIFT = "drift"

    @property
    def run_mode(self) -> RunMode:
        return LEGACY_MODE_ALIASES[self.value]


def coerce_mode(value: Any) -> RunMode:
    if isinstance(value, RunMode):
        return value
    if isinstance(value, Mode):
        return value.run_mode
    s = str(value).lower().replace("-", "_")
    if s in LEGACY_MODE_ALIASES:
        return LEGACY_MODE_ALIASES[s]
    return RunMode(s)


class AccessProfile(str, enum.Enum):
    BLACK_BOX = "black_box"
    GREY_BOX = "grey_box"
    WHITE_BOX = "white_box"


class Severity(str, enum.Enum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"

    @property
    def rank(self) -> int:
        return _SEV_RANK[self]

    @classmethod
    def from_rank(cls, rank: int) -> "Severity":
        rank = max(0, min(rank, len(_SEV_ORDER) - 1))
        return _SEV_ORDER[rank]

    @classmethod
    def max(cls, *items: Optional["Severity"]) -> "Severity":
        present = [r for r in items if r is not None]
        if not present:
            return cls.LOW
        return max(present, key=lambda r: r.rank)


_SEV_ORDER = [Severity.LOW, Severity.MEDIUM, Severity.HIGH, Severity.CRITICAL]
_SEV_RANK = {r: i for i, r in enumerate(_SEV_ORDER)}
Risk = Severity   # legacy name: capability risk uses the same scale, but is a separate field


class RemediationPriority(str, enum.Enum):
    P0 = "P0"
    P1 = "P1"
    P2 = "P2"
    P3 = "P3"


class ChangeKind(str, enum.Enum):
    ADDED = "added"
    REMOVED = "removed"
    DEFINITION_CHANGED = "definition_changed"
    POLICY_CHANGED = "policy_changed"
    ACCESS_CHANGED = "access_changed"
    RUNTIME_CONFIG_CHANGED = "runtime_config_changed"
    COVERAGE_CHANGED = "coverage_changed"
    COMPARISON_INCONCLUSIVE = "comparison_inconclusive"


class ApprovalState(str, enum.Enum):
    APPROVED = "approved"
    PENDING = "pending"
    REJECTED = "rejected"
    UNKNOWN = "unknown"


class Operation(str, enum.Enum):
    """Primary (legacy-compatible) operation class of a tool.

    v2 keeps this as the *primary* class for continuity, and adds the
    independent ``operations`` / ``side_effects`` properties on
    :class:`ToolRecord` and :class:`Capability`.
    """
    READ = "READ"
    WRITE = "WRITE"
    EXEC = "EXEC"
    DELETE = "DELETE"
    UNKNOWN = "UNKNOWN"


# v2 direct-operation vocabulary (TZ §7)
OPS_V2 = ("READ", "CREATE", "UPDATE", "DELETE", "EXECUTE", "PUBLISH", "TRANSMIT")
PRIMARY_TO_OPS = {
    Operation.READ: ["READ"],
    Operation.WRITE: ["CREATE", "UPDATE"],
    Operation.DELETE: ["DELETE"],
    Operation.EXEC: ["EXECUTE"],
    Operation.UNKNOWN: [],
}


class TestResult(str, enum.Enum):
    """Legacy probe result vocabulary (v1).  Kept for the legacy reader."""
    __test__ = False
    PASS = "PASS"
    BLOCKED = "BLOCKED"
    FAIL = "FAIL"
    SKIPPED = "SKIPPED"


class ErrorClass(str, enum.Enum):
    """What kind of failure a control case produced (TZ §2, §12.2)."""
    NONE = "none"
    AUTHORIZATION_REFUSAL = "authorization_refusal"
    SCHEMA_ERROR = "schema_error"
    UNKNOWN_TOOL = "unknown_tool"
    TRANSPORT_ERROR = "transport_error"
    TIMEOUT = "timeout"
    TOOL_ERROR = "tool_error"
    SANDBOX_REFUSED = "sandbox_refused"


class Provenance(str, enum.Enum):
    """Legacy v1 trust levels.  Only used by the legacy reader / import history."""
    DECLARED = "declared"
    EFFECTIVE = "effective"
    VERIFIED = "verified"


# --------------------------------------------------------------------------- #
# Evidence / Claims / Control results
# --------------------------------------------------------------------------- #

@dataclass
class Evidence:
    evidence_id: str
    source_type: SourceType
    method: Method
    locator: Dict[str, Any] = field(default_factory=dict)   # path / symbol / url / key / event_id ...
    digest: Optional[str] = None
    captured_at: Optional[float] = None
    adapter: Optional[str] = None
    adapter_version: Optional[str] = None
    scope: Dict[str, Any] = field(default_factory=dict)     # build / environment / principal / component
    summary: str = ""
    fragment: Optional[str] = None                          # bounded, escaped at report time
    limitations: List[str] = field(default_factory=list)
    extensions: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return plain({f.name: getattr(self, f.name) for f in fields(self)})


@dataclass
class Claim:
    claim_id: str
    statement: str
    claim_status: ClaimStatus
    evidence_refs: List[str] = field(default_factory=list)
    scope: Dict[str, Any] = field(default_factory=dict)
    confidence: Confidence = Confidence.UNKNOWN
    confidence_explanation: str = ""
    limitations: List[str] = field(default_factory=list)
    rule_refs: List[str] = field(default_factory=list)
    component_refs: List[str] = field(default_factory=list)
    source_type: Optional[SourceType] = None
    method: Optional[Method] = None

    def to_dict(self) -> Dict[str, Any]:
        return plain({f.name: getattr(self, f.name) for f in fields(self)})


@dataclass
class ControlResult:
    rule_id: str
    rule_version: str
    applicability: Applicability
    execution_status: ExecutionStatus
    control_outcome: ControlOutcome
    expected_invariant: str = ""
    observed_effect: Optional[str] = None
    interpretation: str = ""
    evaluated_boundary_refs: List[str] = field(default_factory=list)
    component_refs: List[str] = field(default_factory=list)
    claim_refs: List[str] = field(default_factory=list)
    evidence_refs: List[str] = field(default_factory=list)
    finding_refs: List[str] = field(default_factory=list)
    limitations: List[str] = field(default_factory=list)
    missing_sources: List[str] = field(default_factory=list)
    method: Optional[Method] = None
    case_refs: List[str] = field(default_factory=list)   # controlled-validation cases feeding this result
    conditions: Dict[str, Any] = field(default_factory=dict)

    @property
    def counts_for_coverage(self) -> bool:
        return self.control_outcome in (ControlOutcome.PASS, ControlOutcome.FAIL)

    def to_dict(self) -> Dict[str, Any]:
        return plain({f.name: getattr(self, f.name) for f in fields(self)})


# --------------------------------------------------------------------------- #
# Findings
# --------------------------------------------------------------------------- #

@dataclass
class Finding:
    """A structured conclusion (TZ §15.2).

    ``code`` is the signal / finding type (e.g. ``HIDDEN_UNICODE``);
    ``finding_id`` is the *stable* identity derived from rule, boundary,
    component and scope, never from list position, timestamp or severity.
    """
    code: str
    title: str
    description: str
    rule_id: str
    plane: str                                       # capability | definition | behavioral | correlation | memory | identity | infrastructure | context
    verification_status: ClaimStatus = ClaimStatus.HYPOTHESIS
    severity: Optional[Severity] = None              # set when preconditions are established
    potential_severity: Optional[Severity] = None    # for hypotheses
    severity_rationale: str = ""
    rule_version: str = ""
    root_cause: str = ""
    requirement: str = ""
    preconditions: List[str] = field(default_factory=list)
    expected_invariant: str = ""
    component_refs: List[str] = field(default_factory=list)
    boundary_refs: List[str] = field(default_factory=list)
    scope: Dict[str, Any] = field(default_factory=dict)
    claim_refs: List[str] = field(default_factory=list)
    evidence_refs: List[str] = field(default_factory=list)
    observed_effect: Optional[str] = None
    potential_effect: Optional[str] = None
    remediation: str = ""
    remediation_owner: Optional[str] = None
    remediation_priority: Optional[RemediationPriority] = None
    closure_criterion: str = ""
    limitations: List[str] = field(default_factory=list)
    unconfirmed: List[str] = field(default_factory=list)
    related_findings: List[str] = field(default_factory=list)
    memory_stages: Dict[str, StageObservation] = field(default_factory=dict)
    first_seen: Optional[str] = None
    last_seen: Optional[str] = None
    remediation_state: str = "open"                  # open | fixed | accepted | excluded
    reassessment: Dict[str, Any] = field(default_factory=dict)
    server: Optional[str] = None
    tool: Optional[str] = None
    evidence: Dict[str, Any] = field(default_factory=dict)   # inline details (fragment, rule, explanation)
    taxonomy: List[str] = field(default_factory=list)
    finding_id: str = ""
    instance_id: str = ""

    # -- identity ----------------------------------------------------------- #
    def stabilize(self, run_id: str = "") -> "Finding":
        if not self.finding_id:
            where = self.evidence.get("where") if isinstance(self.evidence, dict) else None
            self.finding_id = stable_id(
                "F", self.rule_id, self.code, sorted(self.boundary_refs),
                sorted(self.component_refs) or [self.server, self.tool], where, self.scope,
            )
        if run_id and not self.instance_id:
            self.instance_id = f"{run_id}:{self.finding_id}"
        return self

    @property
    def effective_severity(self) -> Severity:
        return self.severity or self.potential_severity or Severity.LOW

    @property
    def is_confirmed(self) -> bool:
        return self.verification_status in (ClaimStatus.STATIC_SUPPORTED, ClaimStatus.RUNTIME_SUPPORTED)

    def to_dict(self) -> Dict[str, Any]:
        d = plain({f.name: getattr(self, f.name) for f in fields(self)})
        d["effective_severity"] = self.effective_severity.value
        d["memory_stages"] = {k: (v.value if isinstance(v, StageObservation) else v)
                              for k, v in (self.memory_stages or {}).items()}
        return d


# --------------------------------------------------------------------------- #
# Inventory (discovery output)
# --------------------------------------------------------------------------- #

@dataclass
class ToolDefinition:
    name: str
    description: str = ""
    input_schema: Dict[str, Any] = field(default_factory=dict)
    annotations: Dict[str, Any] = field(default_factory=dict)   # MCP tool annotations (self-report)
    output_schema: Optional[Dict[str, Any]] = None
    title: Optional[str] = None
    raw: Dict[str, Any] = field(default_factory=dict)            # original bytes preserved (TZ §6.6)
    declared: Dict[str, Any] = field(default_factory=dict)       # x_audit block of *this tool*: declared, not observed

    @classmethod
    def from_mcp(cls, obj: Dict[str, Any]) -> "ToolDefinition":
        return cls(
            name=str(obj.get("name", "")),
            description=str(obj.get("description") or ""),
            input_schema=obj.get("inputSchema") or obj.get("input_schema") or {},
            annotations=obj.get("annotations") or {},
            output_schema=obj.get("outputSchema") or obj.get("output_schema"),
            title=obj.get("title"),
            raw=obj,
            declared=dict(obj.get("x_audit") or obj.get("x-audit") or {}),
        )

    def parameters(self) -> Dict[str, Dict[str, Any]]:
        props = self.input_schema.get("properties") if isinstance(self.input_schema, dict) else None
        return props if isinstance(props, dict) else {}


@dataclass
class Handshake:
    """Result of a *live* handshake.  ``performed`` is False for config /
    snapshot inventories: a config never fabricates a successful handshake."""
    performed: bool = False
    ok: Optional[bool] = None
    protocol_version: Optional[str] = None
    server_info: Dict[str, Any] = field(default_factory=dict)
    instructions: Optional[str] = None
    error: Optional[str] = None
    source: str = "none"                    # live | snapshot | config | source | none
    captured_at: Optional[float] = None
    identity: Optional[str] = None          # principal / role used for the handshake
    completeness: str = "unknown"           # complete | partial | unavailable | stale | unknown
    notes: List[str] = field(default_factory=list)


@dataclass
class ServerRecord:
    name: str
    transport: str = "stdio"                # stdio | sse | http
    command: Optional[str] = None
    args: List[str] = field(default_factory=list)
    env: Dict[str, str] = field(default_factory=dict)
    url: Optional[str] = None
    declared_capabilities: Dict[str, Any] = field(default_factory=dict)
    handshake: Handshake = field(default_factory=Handshake)
    tools: List["ToolRecord"] = field(default_factory=list)
    resources: List[Dict[str, Any]] = field(default_factory=list)
    prompts: List[Dict[str, Any]] = field(default_factory=list)
    kind: str = "generic"                   # filesystem | postgres | github | shell | fetch | native | generic
    overrides: Dict[str, Any] = field(default_factory=dict)   # x_audit block from config
    effective_access: Dict[str, Any] = field(default_factory=dict)
    component_id: str = ""
    inventory_sources: Dict[str, Any] = field(default_factory=dict)   # configured / source_defined / live_advertised / runtime_observed / policy_authorized
    field_sources: Dict[str, str] = field(default_factory=dict)       # where each config field came from
    is_mcp: bool = True
    capture: Dict[str, Any] = field(default_factory=dict)             # how the configured inventory was captured

    def to_dict(self) -> Dict[str, Any]:
        return {
            "name": self.name,
            "component_id": self.component_id or f"server:{self.name}",
            "kind": self.kind,
            "is_mcp": self.is_mcp,
            "transport": self.transport,
            "command": self.command,
            "args": list(self.args),
            "env_keys": sorted(self.env.keys()),   # never emit secret values
            "url": self.url,
            "declared_capabilities": self.declared_capabilities,
            "handshake": plain(self.handshake),
            "inventory_sources": self.inventory_sources,
            "field_sources": self.field_sources,
            "capture": self.capture,
            "effective_access": self.effective_access,
            "tools": [t.to_dict() for t in self.tools],
            "resources": self.resources,
            "prompts": self.prompts,
        }


@dataclass
class ToolRecord:
    server: str
    definition: ToolDefinition
    classification: Operation = Operation.UNKNOWN        # primary class (legacy-compatible)
    operations: List[str] = field(default_factory=list)  # v2 direct operations
    side_effects: List[Dict[str, Any]] = field(default_factory=list)
    executing_principal: Optional[str] = None
    phase: str = "request_handling"
    target_scope: Dict[str, Any] = field(default_factory=dict)
    classification_basis: str = "definition"             # definition | source_inference | policy_snapshot | runtime_observation
    knowledge_state: KnowledgeState = KnowledgeState.ASSUMED
    destructive: bool = False
    capability_risk: Severity = Severity.MEDIUM          # potential damage of the capability, not a finding severity
    risk_reasons: List[str] = field(default_factory=list)
    effective_access: Dict[str, Any] = field(default_factory=dict)
    egress: bool = False
    sensitive_source: bool = False
    untrusted_input: bool = False
    definition_hash: str = ""
    provenance: Dict[str, str] = field(default_factory=dict)
    declared_hints: Dict[str, Any] = field(default_factory=dict)
    claim_refs: List[str] = field(default_factory=list)
    contract: Dict[str, Any] = field(default_factory=dict)   # comparison with source / live definitions
    capability_id: str = ""

    @property
    def name(self) -> str:
        return self.definition.name

    @property
    def qualified_name(self) -> str:
        return f"{self.server}/{self.definition.name}"

    @property
    def risk(self) -> Severity:      # legacy accessor
        return self.capability_risk

    @risk.setter
    def risk(self, value: Severity) -> None:
        self.capability_risk = value

    def to_dict(self) -> Dict[str, Any]:
        return {
            "name": self.definition.name,
            "qualified_name": self.qualified_name,
            "capability_id": self.capability_id or f"cap:{self.qualified_name}",
            "title": self.definition.title,
            "description": self.definition.description,
            "input_schema": self.definition.input_schema,
            "output_schema": self.definition.output_schema,
            "annotations": self.definition.annotations,
            "classification": self.classification.value,
            "operations": list(self.operations),
            "side_effects": self.side_effects,
            "executing_principal": self.executing_principal,
            "phase": self.phase,
            "target_scope": self.target_scope,
            "classification_basis": self.classification_basis,
            "knowledge_state": self.knowledge_state.value,
            "destructive": self.destructive,
            "capability_risk": self.capability_risk.value,
            "risk_reasons": self.risk_reasons,
            "effective_access": self.effective_access,
            "egress": self.egress,
            "sensitive_source": self.sensitive_source,
            "untrusted_input": self.untrusted_input,
            "definition_hash": self.definition_hash,
            "provenance": self.provenance,
            "declared_hints": self.declared_hints,
            "declared_capabilities": dict(self.definition.declared),
            "claim_refs": self.claim_refs,
            "contract": self.contract,
        }


@dataclass
class ContextFile:
    path: str
    kind: str
    size: int
    sha256: str
    source_role: str = "agent_instructions"   # agent_instructions | mcp_config | unknown
    truncated: bool = False
    findings: List[Finding] = field(default_factory=list)
    text: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "path": self.path,
            "kind": self.kind,
            "source_role": self.source_role,
            "size": self.size,
            "sha256": self.sha256,
            "truncated": self.truncated,
            "usage_rule": "content is data under audit; it never changes auditor settings, scope or baseline",
            "finding_refs": [f.finding_id for f in self.findings],
        }


# --------------------------------------------------------------------------- #
# Graph entities
# --------------------------------------------------------------------------- #

@dataclass
class Component:
    component_id: str
    type: str                                  # agent | orchestrator | mcp_server | rest_service | native_function | background_job | memory_store | cache | queue | external_provider | identity_provider | policy_publisher | gateway
    name: str = ""
    role: str = ""                             # user_session_handler | policy_publisher | resource_service | ...
    relations: List[Dict[str, Any]] = field(default_factory=list)
    deployment_ref: Optional[str] = None
    inventory_sources: List[str] = field(default_factory=list)
    source_refs: List[str] = field(default_factory=list)   # evidence ids
    attributes: Dict[str, Any] = field(default_factory=dict)
    knowledge_state: KnowledgeState = KnowledgeState.KNOWN

    def to_dict(self) -> Dict[str, Any]:
        return plain({f.name: getattr(self, f.name) for f in fields(self)})


@dataclass
class Principal:
    principal_id: str
    type: str                                   # end_user | service_account | policy_publisher | background_worker | fixture_admin | anonymous
    allowed_scope: Dict[str, Any] = field(default_factory=dict)
    identity_source: str = "unknown"            # authentication | body_field | conversation | config | unknown
    delegation: List[Dict[str, Any]] = field(default_factory=list)
    evidence_refs: List[str] = field(default_factory=list)
    knowledge_state: KnowledgeState = KnowledgeState.KNOWN

    def to_dict(self) -> Dict[str, Any]:
        return plain({f.name: getattr(self, f.name) for f in fields(self)})


@dataclass
class Capability:
    capability_id: str
    component_ref: str
    operations: List[str] = field(default_factory=list)
    direct_effects: List[str] = field(default_factory=list)
    side_effects: List[Dict[str, Any]] = field(default_factory=list)
    executing_principal: Optional[str] = None
    phase: str = "request_handling"
    target: Dict[str, Any] = field(default_factory=dict)      # object / scope
    basis: str = "definition"
    knowledge_state: KnowledgeState = KnowledgeState.ASSUMED
    claim_refs: List[str] = field(default_factory=list)
    evidence_refs: List[str] = field(default_factory=list)
    attributes: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return plain({f.name: getattr(self, f.name) for f in fields(self)})


@dataclass
class MemoryStoreRecord:
    component_id: str
    store_type: str                              # redis | mongodb | vector | sql | file | unknown
    memory_types: List[Dict[str, Any]] = field(default_factory=list)   # {type, audience, authority, scope_model}
    read_principals: List[str] = field(default_factory=list)
    write_principals: List[str] = field(default_factory=list)
    publish_principals: List[str] = field(default_factory=list)
    observability: Dict[str, Any] = field(default_factory=dict)
    retention: Dict[str, Any] = field(default_factory=dict)
    evidence_refs: List[str] = field(default_factory=list)
    knowledge_state: KnowledgeState = KnowledgeState.UNKNOWN

    def to_dict(self) -> Dict[str, Any]:
        return plain({f.name: getattr(self, f.name) for f in fields(self)})


@dataclass
class TrustBoundary:
    boundary_id: str
    from_ref: str
    to_ref: str
    rule: str = ""
    enforcement_point: Optional[str] = None
    delegation: Optional[str] = None
    conditions: List[str] = field(default_factory=list)
    expected_access: Dict[str, Any] = field(default_factory=dict)
    scope: Dict[str, Any] = field(default_factory=dict)
    observation_status: str = "not_observed"     # observed | not_observed | unknown
    basis: List[str] = field(default_factory=list)   # evidence ids
    knowledge_state: KnowledgeState = KnowledgeState.ASSUMED

    def to_dict(self) -> Dict[str, Any]:
        return plain({f.name: getattr(self, f.name) for f in fields(self)})


@dataclass
class Edge:
    edge_id: str
    from_ref: str
    to_ref: str
    kind: str                                    # data_flow | control_flow | memory_write | memory_read | publish | transmit | auth_transition
    basis: List[str] = field(default_factory=list)      # evidence ids
    conditions: List[str] = field(default_factory=list)
    expected_boundary: Optional[str] = None
    scope: Dict[str, Any] = field(default_factory=dict)
    state: PathState = PathState.UNKNOWN
    claim_refs: List[str] = field(default_factory=list)
    attributes: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return plain({f.name: getattr(self, f.name) for f in fields(self)})


# --------------------------------------------------------------------------- #
# Coverage
# --------------------------------------------------------------------------- #

@dataclass
class CoverageMetric:
    metric: str
    numerator: Optional[int]
    denominator: Optional[int]
    denominator_source: str = ""
    method: str = ""
    unknown: int = 0
    gaps: List[str] = field(default_factory=list)
    limitation: str = ""
    details: Dict[str, Any] = field(default_factory=dict)

    @property
    def ratio(self) -> Optional[float]:
        if self.numerator is None or not self.denominator:
            return None
        return round(self.numerator / self.denominator, 4)

    @property
    def display(self) -> str:
        if self.ratio is None:
            return "не определено"
        return f"{self.numerator}/{self.denominator} ({self.ratio * 100:.1f}%)"

    def to_dict(self) -> Dict[str, Any]:
        d = plain({f.name: getattr(self, f.name) for f in fields(self)})
        d["ratio"] = self.ratio
        d["display"] = self.display
        return d


# --------------------------------------------------------------------------- #
# Controlled validation cases
# --------------------------------------------------------------------------- #

@dataclass
class ControlCaseResult:
    """One executed (or skipped) control case of the behavioural plane."""
    id: str
    name: str
    server: str
    tool: Optional[str]
    rule_id: str
    expected: str                                    # allowed | denied
    execution_status: ExecutionStatus
    control_outcome: ControlOutcome
    applicability: Applicability = Applicability.APPLICABLE
    error_class: ErrorClass = ErrorClass.NONE
    observed_effect: Dict[str, Any] = field(default_factory=dict)    # {kind, observed: bool|None, details}
    expected_invariant: str = ""
    boundary_ref: Optional[str] = None
    evaluated_boundary_refs: List[str] = field(default_factory=list)
    evidence_refs: List[str] = field(default_factory=list)
    claim_refs: List[str] = field(default_factory=list)
    limitations: List[str] = field(default_factory=list)
    details: str = ""
    arguments: Dict[str, Any] = field(default_factory=dict)
    raw_summary: str = ""
    fixture: Dict[str, Any] = field(default_factory=dict)            # setup / teardown status
    prepared_by: Optional[str] = None                                # fixture_admin | user_session | None

    def to_dict(self) -> Dict[str, Any]:
        return plain({f.name: getattr(self, f.name) for f in fields(self)})


# Legacy alias kept for imports; the v1 ``ProbeResult`` semantics are gone.
ProbeResult = ControlCaseResult


# --------------------------------------------------------------------------- #
# Adapter status
# --------------------------------------------------------------------------- #

@dataclass
class AdapterStatus:
    adapter_id: str
    kind: str
    adapter_version: str
    status: str                                       # available | unavailable | partial | stale | skipped
    supported: List[str] = field(default_factory=list)
    unsupported: Dict[str, str] = field(default_factory=dict)
    reasons: List[str] = field(default_factory=list)
    binding: Dict[str, Any] = field(default_factory=dict)
    captured_at: Optional[float] = None
    evidence_count: int = 0

    def to_dict(self) -> Dict[str, Any]:
        return plain({f.name: getattr(self, f.name) for f in fields(self)})


# --------------------------------------------------------------------------- #
# The audit document
# --------------------------------------------------------------------------- #

@dataclass
class AuditDocument:
    mode: RunMode = RunMode.OFFLINE
    access_profile: AccessProfile = AccessProfile.GREY_BOX
    run_id: str = ""
    target: Dict[str, Any] = field(default_factory=dict)           # id / build_ref / environment / boundaries
    servers: List[ServerRecord] = field(default_factory=list)
    agent_context: List[ContextFile] = field(default_factory=list)
    components: List[Component] = field(default_factory=list)
    principals: List[Principal] = field(default_factory=list)
    capabilities: List[Capability] = field(default_factory=list)
    memory_stores: List[MemoryStoreRecord] = field(default_factory=list)
    boundaries: List[TrustBoundary] = field(default_factory=list)
    edges: List[Edge] = field(default_factory=list)
    evidence: List[Evidence] = field(default_factory=list)
    claims: List[Claim] = field(default_factory=list)
    control_results: List[ControlResult] = field(default_factory=list)
    findings: List[Finding] = field(default_factory=list)
    tests: List[ControlCaseResult] = field(default_factory=list)
    memory_cases: List[Dict[str, Any]] = field(default_factory=list)
    coverage: List[CoverageMetric] = field(default_factory=list)
    hash_baseline: Dict[str, str] = field(default_factory=dict)
    collisions: List[Dict[str, Any]] = field(default_factory=list)
    mcp_scan: Dict[str, Any] = field(default_factory=dict)
    inventory_reconciliation: List[Dict[str, Any]] = field(default_factory=list)
    adapters: List[AdapterStatus] = field(default_factory=list)
    plan: Dict[str, Any] = field(default_factory=dict)
    trifecta: Dict[str, Any] = field(default_factory=dict)
    summary: Dict[str, Any] = field(default_factory=dict)
    verdict: Dict[str, Any] = field(default_factory=dict)
    downstream: Dict[str, Any] = field(default_factory=dict)
    drift: Dict[str, Any] = field(default_factory=dict)
    import_history: Dict[str, Any] = field(default_factory=dict)
    limitations: List[str] = field(default_factory=list)
    meta: Dict[str, Any] = field(default_factory=dict)
    profile: Dict[str, Any] = field(default_factory=dict)
    policy: Dict[str, Any] = field(default_factory=dict)
    source_facts: Dict[str, Any] = field(default_factory=dict)
    deployment: Dict[str, Any] = field(default_factory=dict)
    trace_events: List[Dict[str, Any]] = field(default_factory=list)
    memory_records: List[Dict[str, Any]] = field(default_factory=list)
    memory_events: List[Dict[str, Any]] = field(default_factory=list)
    status: str = "running"                                       # running | completed | partial | failed
    started_at: float = field(default_factory=time.time)
    finished_at: Optional[float] = None

    # -- helpers ------------------------------------------------------------ #
    def all_tools(self) -> List[ToolRecord]:
        return [t for s in self.servers for t in s.tools]

    def server(self, name: str) -> Optional[ServerRecord]:
        for s in self.servers:
            if s.name == name:
                return s
        return None

    def server_refs(self, server: ServerRecord) -> List[str]:
        """Every name this server is referenced by: its inventory name, its component id and the
        profile's ``servers`` alias (``{"mcp name": "component id"}``).  Source facts, policies and
        profiles name the same server differently; matching on one name only loses the link."""
        aliases = self.profile.get("servers") or {}
        refs = [server.name, server.component_id]
        if isinstance(aliases, dict):
            target = aliases.get(server.name) or aliases.get(server.component_id)
            if isinstance(target, str):
                refs.append(target)
            refs += [k for k, v in aliases.items() if v in (server.name, server.component_id)]
        return [r for r in dict.fromkeys(refs) if r]

    def server_by_kind(self, kind: str) -> Optional[ServerRecord]:
        for s in self.servers:
            if s.kind == kind:
                return s
        return None

    def component(self, component_id: str) -> Optional[Component]:
        for c in self.components:
            if c.component_id == component_id:
                return c
        return None

    def components_by_role(self, role: str) -> List[Component]:
        return [c for c in self.components if c.role == role]

    def components_by_type(self, ctype: str) -> List[Component]:
        return [c for c in self.components if c.type == ctype]

    def claim(self, claim_id: str) -> Optional[Claim]:
        for c in self.claims:
            if c.claim_id == claim_id:
                return c
        return None

    def evidence_by_id(self, evidence_id: str) -> Optional[Evidence]:
        for e in self.evidence:
            if e.evidence_id == evidence_id:
                return e
        return None

    def control_result(self, rule_id: str) -> Optional[ControlResult]:
        for r in self.control_results:
            if r.rule_id == rule_id:
                return r
        return None

    @property
    def definition_findings(self) -> List[Finding]:
        return [f for f in self.findings if f.plane in ("definition", "context")]

    @property
    def security_findings(self) -> List[Finding]:
        return [f for f in self.findings if f.plane not in ("definition", "context")]

    def has_source(self, kind: str) -> bool:
        return any(a.kind == kind and a.status in ("available", "partial") for a in self.adapters)

    def source_status(self, kind: str) -> str:
        for a in self.adapters:
            if a.kind == kind:
                return a.status
        return "missing"

    @property
    def runtime_validation_performed(self) -> bool:
        return any(t.execution_status == ExecutionStatus.COMPLETED for t in self.tests) or \
            any(e.source_type in RUNTIME_SOURCE_TYPES for e in self.evidence)

    @property
    def effective_capabilities(self) -> Dict[str, Any]:
        return {s.name: s.effective_access for s in self.servers}

    def add_finding(self, f: Finding) -> Finding:
        f.stabilize(self.run_id)
        for existing in self.findings:
            if existing.finding_id == f.finding_id:
                # same root cause reported by another section: merge references, keep one finding
                for attr in ("claim_refs", "evidence_refs", "related_findings", "limitations"):
                    merged = list(getattr(existing, attr))
                    for v in getattr(f, attr):
                        if v not in merged:
                            merged.append(v)
                    setattr(existing, attr, merged)
                return existing
        self.findings.append(f)
        return f

    def to_dict(self) -> Dict[str, Any]:
        from . import AUDIT_SCHEMA, AUDIT_SCHEMA_VERSION, RULESET_VERSION, ENGINE_VERSION
        meta = dict(self.meta)
        meta.setdefault("schema_version", AUDIT_SCHEMA_VERSION)
        meta.setdefault("engine_version", ENGINE_VERSION)
        meta.setdefault("ruleset_version", RULESET_VERSION)
        meta["mode"] = self.mode.value
        meta["access_profile"] = self.access_profile.value
        meta["run_id"] = self.run_id
        meta["target"] = self.target
        meta["runtime_validation_performed"] = self.runtime_validation_performed
        meta["status"] = self.status
        meta["started_at"] = self.started_at
        meta["finished_at"] = self.finished_at
        return {
            "schema": AUDIT_SCHEMA,
            "schema_version": AUDIT_SCHEMA_VERSION,
            "meta": meta,
            "target": self.target,
            "adapters": [a.to_dict() for a in self.adapters],
            "plan": self.plan,
            "inventory": {
                "servers": [s.to_dict() for s in self.servers],
                "agent_context": [c.to_dict() for c in self.agent_context],
                "reconciliation": self.inventory_reconciliation,
            },
            "components": [c.to_dict() for c in self.components],
            "principals": [p.to_dict() for p in self.principals],
            "capabilities": [c.to_dict() for c in self.capabilities],
            "memory_stores": [m.to_dict() for m in self.memory_stores],
            "boundaries": [b.to_dict() for b in self.boundaries],
            "edges": [e.to_dict() for e in self.edges],
            "definition_analysis": {
                "finding_refs": [f.finding_id for f in self.definition_findings],
                "hash_baseline": dict(sorted(self.hash_baseline.items())),
                "canonicalization_version": meta.get("canonicalization_version"),
                "collisions": self.collisions,
                "mcp_scan": self.mcp_scan,
            },
            "evidence": [e.to_dict() for e in self.evidence],
            "claims": [c.to_dict() for c in self.claims],
            "control_results": [r.to_dict() for r in self.control_results],
            "findings": [f.to_dict() for f in self.findings],
            "tests": [t.to_dict() for t in self.tests],
            "memory_cases": self.memory_cases,
            "coverage": [c.to_dict() for c in self.coverage],
            "trifecta": self.trifecta,
            "summary": self.summary,
            "verdict": self.verdict,
            "downstream": self.downstream,
            "drift": self.drift,
            "import_history": self.import_history,
            "limitations": self.limitations,
        }
