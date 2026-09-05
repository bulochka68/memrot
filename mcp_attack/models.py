"""Data model shared by every layer of the attack harness.

Design rules (mirrors ``mcp_audit/models.py`` in spirit, but is a standalone
copy -- no import from ``mcp_audit``, only loose string-tag alignment on
``rule_ids``/``taxonomy``):

* an attack attempt never silently disappears: every :class:`AttackResult`
  has a :class:`Verdict`, including ``ERROR`` and ``NOT_EVALUATED``;
* the Attack-Success-Rate denominator is never fabricated: a
  :class:`GroupMetric` with ``total == 0`` displays ``"n/a (0/0)"``, never a
  100% or 0% that nobody attempted;
* ``INVALID`` (stale contamination from a previous run) and ``ERROR``
  (adapter/transport failure) are always visible via ``counts_by_verdict``
  even though they are excluded from the ASR ratio itself.
"""
from __future__ import annotations

import enum
import hashlib
import json
import time
from dataclasses import dataclass, field, fields, is_dataclass
from typing import Any, Dict, Iterable, List, Optional


# --------------------------------------------------------------------------- #
# Helpers (local copies -- not imported from mcp_audit)
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
    payload = "|".join("" if p is None else json.dumps(plain(p), sort_keys=True, ensure_ascii=False)
                       for p in parts)
    return f"{prefix}-{hashlib.sha256(payload.encode('utf-8')).hexdigest()[:length]}"


# --------------------------------------------------------------------------- #
# Vocabularies
# --------------------------------------------------------------------------- #

class AccessProfileTag(str, enum.Enum):
    """Values match ``mcp_audit.models.AccessProfile`` -- not imported, just aligned."""
    BLACK_BOX = "black_box"
    GREY_BOX = "grey_box"
    WHITE_BOX = "white_box"


class ChannelRole(str, enum.Enum):
    ATTACKER = "attacker"
    VICTIM = "victim"
    BENIGN_CONTROL = "benign_control"


class Verdict(str, enum.Enum):
    CONFIRMED = "CONFIRMED"       # canary absent before, present after: the technique poked through
    CLEAN = "CLEAN"                 # canary absent before and after: not reproduced (or not vulnerable)
    INVALID = "INVALID"              # canary already present before the attack ran: stale contamination
    ERROR = "ERROR"                   # adapter/transport failure
    NOT_EVALUATED = "NOT_EVALUATED"    # required access profile not met by the bound adapter


class DetectionChannel(str, enum.Enum):
    RESPONSE_TEXT = "response_text"
    MEMORY_INSPECTION = "memory_inspection"
    GROUND_TRUTH = "ground_truth"


# --------------------------------------------------------------------------- #
# Channels / principals
# --------------------------------------------------------------------------- #

@dataclass
class Principal:
    principal_id: str
    credential_ref: Optional[str] = None   # resolved as MCP_ATTACK_CRED_<credential_ref>
    label: str = ""
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return plain({f.name: getattr(self, f.name) for f in fields(self)})


@dataclass
class Channel:
    role: ChannelRole
    principal: Principal
    channel_id: str = ""

    def __post_init__(self) -> None:
        if not self.channel_id:
            self.channel_id = f"{self.role.value}:{self.principal.principal_id}"

    def to_dict(self) -> Dict[str, Any]:
        return {"role": self.role.value, "channel_id": self.channel_id, "principal": self.principal.to_dict()}


# --------------------------------------------------------------------------- #
# Attack catalog
# --------------------------------------------------------------------------- #

FRAMING_VALUES = ("explicit_rule", "authority_compliance", "implicit_generalization",
                  "third_party_relay", "minja_bridging", "none")
PAYLOAD_VALUES = ("formatting_marker", "false_citation_policy", "disclaimer_suppression",
                  "access_control_adjacent", "none")
LAYER_VALUES = ("policy_global", "semantic", "episodic", "none")
PROPAGATION_VALUES = ("cross-user", "cross-session-same-user", "single-turn")


@dataclass
class AttackVariant:
    id: str
    title: str
    framing: str
    payload: str
    layer: str
    propagation: str
    probe: str
    canary_template: str = ""                    # "{canary}" substituted into inject_turns/probe
    inject_turns: List[str] = field(default_factory=list)
    rule_ids: List[str] = field(default_factory=list)     # loose string-tag link to mcp_audit's rule catalogue
    taxonomy: List[str] = field(default_factory=list)      # MITRE ATLAS ids, e.g. "AML.T0051"
    access_profile_required: str = "black_box"
    attacker_role: str = "attacker"
    victim_role: str = "victim"
    attacker_principal: Optional[str] = None       # disambiguates when >1 channel shares attacker_role
    victim_principal: Optional[str] = None
    target_ref: Optional[str] = None                 # e.g. a foreign customer id, for ground_truth_check()
    rule_semantic: Optional[str] = None               # phase-2 LLM-judge rubric text
    source: str = "static_catalog"                     # static_catalog | llm_mutation | imported:<bank>
    notes: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return plain({f.name: getattr(self, f.name) for f in fields(self)})


# --------------------------------------------------------------------------- #
# Trace / detection / results
# --------------------------------------------------------------------------- #

@dataclass
class TurnRecord:
    """What gets logged per request/response (also see tracer.TraceEvent, the on-disk form)."""
    phase: str
    channel_id: str
    principal_id: str
    session_id: Optional[str]
    direction: str                 # request | response | inspection
    text: str = ""
    canary_present: Optional[bool] = None
    error: Optional[str] = None
    ts: float = field(default_factory=time.time)

    def to_dict(self) -> Dict[str, Any]:
        return plain({f.name: getattr(self, f.name) for f in fields(self)})


@dataclass
class DetectionResult:
    canary_present: bool
    channel: DetectionChannel
    detail: str = ""
    evidence_ref: Optional[str] = None   # trace event_id

    def to_dict(self) -> Dict[str, Any]:
        return plain({f.name: getattr(self, f.name) for f in fields(self)})


@dataclass
class AttackResult:
    variant_id: str
    verdict: Verdict
    baseline_detection: Optional[DetectionResult] = None
    post_detection: Optional[DetectionResult] = None
    ground_truth_detection: Optional[DetectionResult] = None
    rule_ids: List[str] = field(default_factory=list)
    taxonomy: List[str] = field(default_factory=list)
    framing: str = ""
    payload: str = ""
    layer: str = ""
    propagation: str = ""
    channels_used: List[str] = field(default_factory=list)
    canary: str = ""
    started_at: float = field(default_factory=time.time)
    finished_at: Optional[float] = None
    error: Optional[str] = None
    limitations: List[str] = field(default_factory=list)
    trace_event_ids: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return plain({f.name: getattr(self, f.name) for f in fields(self)})


# --------------------------------------------------------------------------- #
# Reporting
# --------------------------------------------------------------------------- #

@dataclass
class GroupMetric:
    """Mirrors mcp_audit.models.CoverageMetric's "never fabricate a percentage" convention."""
    key: str
    confirmed: int = 0
    total: int = 0   # CONFIRMED + CLEAN only -- INVALID/ERROR/NOT_EVALUATED never enter this ratio

    @property
    def ratio(self) -> Optional[float]:
        if self.total == 0:
            return None
        return round(self.confirmed / self.total, 4)

    @property
    def display(self) -> str:
        if self.total == 0:
            return "n/a (0/0)"
        return f"{self.confirmed}/{self.total} ({self.ratio * 100:.1f}%)"

    def to_dict(self) -> Dict[str, Any]:
        d = plain({f.name: getattr(self, f.name) for f in fields(self)})
        d["ratio"] = self.ratio
        d["display"] = self.display
        return d


@dataclass
class RunReport:
    run_id: str
    target_id: str
    started_at: float = field(default_factory=time.time)
    finished_at: Optional[float] = None
    results: List[AttackResult] = field(default_factory=list)
    channels: List[Channel] = field(default_factory=list)
    overall_asr: Optional[GroupMetric] = None
    asr_by_rule_id: Dict[str, GroupMetric] = field(default_factory=dict)
    asr_by_axis: Dict[str, Dict[str, GroupMetric]] = field(default_factory=dict)
    counts_by_verdict: Dict[str, int] = field(default_factory=dict)
    limitations: List[str] = field(default_factory=list)
    trace_path: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "run_id": self.run_id,
            "target_id": self.target_id,
            "started_at": self.started_at,
            "finished_at": self.finished_at,
            "channels": [c.to_dict() for c in self.channels],
            "results": [r.to_dict() for r in self.results],
            "overall_asr": self.overall_asr.to_dict() if self.overall_asr else None,
            "asr_by_rule_id": {k: v.to_dict() for k, v in self.asr_by_rule_id.items()},
            "asr_by_axis": {axis: {k: v.to_dict() for k, v in groups.items()}
                           for axis, groups in self.asr_by_axis.items()},
            "counts_by_verdict": dict(self.counts_by_verdict),
            "limitations": list(self.limitations),
            "trace_path": self.trace_path,
        }


def default_run_id() -> str:
    return stable_id("run", time.time())[:14]
