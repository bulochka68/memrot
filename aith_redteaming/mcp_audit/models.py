"""Single data model shared by all layers == the ``audit v1.1`` JSON.

Everything the orchestrator passes between layers lives here, so the
in-memory representation and the emitted artifact never diverge.
"""
from __future__ import annotations

import enum
from dataclasses import dataclass, field, asdict
from typing import Any, Dict, List, Optional


class Provenance(str, enum.Enum):
    DECLARED = "declared"    # server self-report; never trusted for the verdict
    EFFECTIVE = "effective"  # derived from config / permissions
    VERIFIED = "verified"    # confirmed by an active probe


class Operation(str, enum.Enum):
    READ = "READ"
    WRITE = "WRITE"
    EXEC = "EXEC"
    DELETE = "DELETE"        # WRITE + destructive
    UNKNOWN = "UNKNOWN"


class Risk(str, enum.Enum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"

    @property
    def rank(self) -> int:
        return _RISK_RANK[self]

    @classmethod
    def from_rank(cls, rank: int) -> "Risk":
        rank = max(0, min(rank, len(_RISK_ORDER) - 1))
        return _RISK_ORDER[rank]

    @classmethod
    def max(cls, *risks: "Risk") -> "Risk":
        risks = [r for r in risks if r is not None]
        if not risks:
            return cls.LOW
        return max(risks, key=lambda r: r.rank)


_RISK_ORDER = [Risk.LOW, Risk.MEDIUM, Risk.HIGH, Risk.CRITICAL]
_RISK_RANK = {r: i for i, r in enumerate(_RISK_ORDER)}


class TestResult(str, enum.Enum):
    __test__ = False  # not a pytest test class
    PASS = "PASS"          # the probe succeeded (the capability is real)
    BLOCKED = "BLOCKED"    # the server refused (boundary holds)
    FAIL = "FAIL"          # the probe could not be evaluated (error / timeout)
    SKIPPED = "SKIPPED"    # not applicable / not run (passive mode)


class Mode(str, enum.Enum):
    PASSIVE = "passive"
    ACTIVE = "active"
    DRIFT = "drift"


# --------------------------------------------------------------------------- #
# Findings
# --------------------------------------------------------------------------- #

@dataclass
class Finding:
    """A single audit finding.  ``plane`` says which audit plane produced it."""
    id: str
    type: str
    severity: Risk
    title: str
    description: str
    plane: str                              # capability | definition | behavioral | correlation
    provenance: Provenance
    server: Optional[str] = None
    tool: Optional[str] = None
    evidence: Dict[str, Any] = field(default_factory=dict)
    taxonomy: List[str] = field(default_factory=list)   # e.g. ["AML.T0068"]

    def to_dict(self) -> Dict[str, Any]:
        d = asdict(self)
        d["severity"] = self.severity.value
        d["provenance"] = self.provenance.value
        return d


# --------------------------------------------------------------------------- #
# Discovery output (raw graph)
# --------------------------------------------------------------------------- #

@dataclass
class ToolDefinition:
    name: str
    description: str = ""
    input_schema: Dict[str, Any] = field(default_factory=dict)
    annotations: Dict[str, Any] = field(default_factory=dict)   # MCP tool annotations (declared)
    output_schema: Optional[Dict[str, Any]] = None
    title: Optional[str] = None
    raw: Dict[str, Any] = field(default_factory=dict)

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
        )


@dataclass
class Handshake:
    ok: bool = False
    protocol_version: Optional[str] = None
    server_info: Dict[str, Any] = field(default_factory=dict)
    instructions: Optional[str] = None      # server-supplied system instructions (definition plane!)
    error: Optional[str] = None
    source: str = "none"                    # live | snapshot | config | none


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
    kind: str = "generic"                   # filesystem | postgres | github | shell | fetch | generic
    overrides: Dict[str, Any] = field(default_factory=dict)   # x_audit block from config
    effective_access: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "name": self.name,
            "kind": self.kind,
            "transport": self.transport,
            "command": self.command,
            "args": list(self.args),
            "env_keys": sorted(self.env.keys()),   # never emit secret values
            "url": self.url,
            "declared_capabilities": self.declared_capabilities,
            "handshake": asdict(self.handshake),
            "effective_access": self.effective_access,
            "tools": [t.to_dict() for t in self.tools],
            "resources": self.resources,
            "prompts": self.prompts,
        }


# --------------------------------------------------------------------------- #
# Classified tool record (layer 3 output)
# --------------------------------------------------------------------------- #

@dataclass
class ToolRecord:
    server: str
    definition: ToolDefinition
    classification: Operation = Operation.UNKNOWN
    destructive: bool = False
    risk: Risk = Risk.MEDIUM
    risk_reasons: List[str] = field(default_factory=list)
    effective_access: Dict[str, Any] = field(default_factory=dict)
    egress: bool = False                    # can move data off-host
    sensitive_source: bool = False          # reads secrets / private data
    untrusted_input: bool = False           # returns attacker-controllable content
    verified: Optional[bool] = None         # None = never probed
    definition_hash: str = ""
    provenance: Dict[str, str] = field(default_factory=dict)
    declared_hints: Dict[str, Any] = field(default_factory=dict)

    @property
    def name(self) -> str:
        return self.definition.name

    @property
    def qualified_name(self) -> str:
        return f"{self.server}/{self.definition.name}"

    def to_dict(self) -> Dict[str, Any]:
        return {
            "name": self.definition.name,
            "title": self.definition.title,
            "description": self.definition.description,
            "input_schema": self.definition.input_schema,
            "annotations": self.definition.annotations,
            "classification": self.classification.value,
            "destructive": self.destructive,
            "risk": self.risk.value,
            "risk_reasons": self.risk_reasons,
            "effective_access": self.effective_access,
            "egress": self.egress,
            "sensitive_source": self.sensitive_source,
            "untrusted_input": self.untrusted_input,
            "verified": self.verified,
            "definition_hash": self.definition_hash,
            "provenance": self.provenance,
            "declared_hints": self.declared_hints,
        }


# --------------------------------------------------------------------------- #
# Agent context files
# --------------------------------------------------------------------------- #

@dataclass
class ContextFile:
    path: str
    kind: str                       # claude_md | cursorrules | copilot_instructions | agents_md | ...
    size: int
    sha256: str
    findings: List[Finding] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "path": self.path,
            "kind": self.kind,
            "size": self.size,
            "sha256": self.sha256,
            "findings": [f.to_dict() for f in self.findings],
        }


# --------------------------------------------------------------------------- #
# Active probes
# --------------------------------------------------------------------------- #

@dataclass
class ProbeResult:
    id: str
    name: str
    server: str
    tool: Optional[str]
    result: TestResult
    expected: TestResult
    severity: Risk
    details: str = ""
    evidence: Dict[str, Any] = field(default_factory=dict)

    @property
    def boundary_holds(self) -> bool:
        return self.result == self.expected

    def to_dict(self) -> Dict[str, Any]:
        d = asdict(self)
        d["result"] = self.result.value
        d["expected"] = self.expected.value
        d["severity"] = self.severity.value
        d["boundary_holds"] = self.boundary_holds
        d["provenance"] = Provenance.VERIFIED.value
        return d


# --------------------------------------------------------------------------- #
# The audit document
# --------------------------------------------------------------------------- #

@dataclass
class AuditDocument:
    mode: Mode
    servers: List[ServerRecord] = field(default_factory=list)
    agent_context: List[ContextFile] = field(default_factory=list)
    definition_findings: List[Finding] = field(default_factory=list)
    hash_baseline: Dict[str, str] = field(default_factory=dict)
    collisions: List[Dict[str, Any]] = field(default_factory=list)
    mcp_scan: Dict[str, Any] = field(default_factory=dict)
    tests: List[ProbeResult] = field(default_factory=list)
    security_findings: List[Finding] = field(default_factory=list)
    summary: Dict[str, Any] = field(default_factory=dict)
    verdict: Dict[str, Any] = field(default_factory=dict)
    downstream: Dict[str, Any] = field(default_factory=dict)
    drift: Dict[str, Any] = field(default_factory=dict)
    meta: Dict[str, Any] = field(default_factory=dict)

    # -- helpers ------------------------------------------------------------ #
    def all_tools(self) -> List[ToolRecord]:
        return [t for s in self.servers for t in s.tools]

    def server_by_kind(self, kind: str) -> Optional[ServerRecord]:
        for s in self.servers:
            if s.kind == kind:
                return s
        return None

    def server(self, name: str) -> Optional[ServerRecord]:
        for s in self.servers:
            if s.name == name:
                return s
        return None

    @property
    def effective_capabilities(self) -> Dict[str, Any]:
        return {s.name: s.effective_access for s in self.servers}

    def to_dict(self) -> Dict[str, Any]:
        from . import AUDIT_SCHEMA_VERSION
        return {
            "schema": "audit",
            "version": AUDIT_SCHEMA_VERSION,
            "mode": self.mode.value,
            "meta": self.meta,
            "servers": [s.to_dict() for s in self.servers],
            "agent_context": [c.to_dict() for c in self.agent_context],
            "definition_analysis": {
                "findings": [f.to_dict() for f in self.definition_findings],
                "hash_baseline": dict(sorted(self.hash_baseline.items())),
                "collisions": self.collisions,
                "mcp_scan": self.mcp_scan,
            },
            "effective_capabilities": self.effective_capabilities,
            "tests": [t.to_dict() for t in self.tests],
            "security_findings": [f.to_dict() for f in self.security_findings],
            "summary": self.summary,
            "verdict": self.verdict,
            "downstream": self.downstream,
            "drift": self.drift,
        }
